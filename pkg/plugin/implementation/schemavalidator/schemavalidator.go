package schemavalidator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/beckn-one/beckn-onix/pkg/log"
	"github.com/beckn-one/beckn-onix/pkg/model"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Payload represents the structure of the data payload with context information.
type payload struct {
	Context struct {
		Domain      string `json:"domain"`
		Version     string `json:"version,omitempty"`
		CoreVersion string `json:"core_version,omitempty"`
	} `json:"context"`
}

var errSchemaKeyNotFound = errors.New("schema key not found")

// schemaValidator implements the Validator interface.
type schemaValidator struct {
	config      *Config
	schemaCache map[string]*jsonschema.Schema
	schemaFiles map[string]string
	compiler    *jsonschema.Compiler
	cacheMu     sync.RWMutex
	compileMu   sync.Mutex
}

// Config struct for SchemaValidator.
type Config struct {
	SchemaDir string
}

// New creates a new ValidatorProvider instance.
func New(ctx context.Context, config *Config) (*schemaValidator, func() error, error) {
	// Check if config is nil
	if config == nil {
		return nil, nil, fmt.Errorf("config cannot be nil")
	}
	v := &schemaValidator{
		config:      config,
		schemaCache: make(map[string]*jsonschema.Schema),
		schemaFiles: make(map[string]string),
		compiler:    jsonschema.NewCompiler(),
	}

	// Call Initialise function to load schemas and get validators
	if err := v.initialise(); err != nil {
		return nil, nil, fmt.Errorf("failed to initialise schemaValidator: %v", err)
	}
	return v, nil, nil
}

// Validate validates the given data against the schema.
func (v *schemaValidator) Validate(ctx context.Context, url *url.URL, data []byte) error {
	var payloadData payload
	err := json.Unmarshal(data, &payloadData)
	if err != nil {
		return model.NewBadReqErr(fmt.Errorf("failed to parse JSON payload: %v", err))
	}

	if payloadData.Context.Domain == "" {
		return model.NewBadReqErr(fmt.Errorf("missing field Domain in context"))
	}
	if payloadData.Context.Version == "" && payloadData.Context.CoreVersion == "" {
		return model.NewBadReqErr(fmt.Errorf("missing field Version or CoreVersion in context"))
	}
	if payloadData.Context.Version == "" {
		payloadData.Context.Version = payloadData.Context.CoreVersion
	} else if payloadData.Context.CoreVersion == "" {
		payloadData.Context.CoreVersion = payloadData.Context.Version
	}

	// Extract domain, version, and endpoint from the payload and uri.
	cxtDomain := payloadData.Context.Domain
	version := payloadData.Context.Version
	version = fmt.Sprintf("v%s", version)

	endpoint := path.Base(url.String())
	log.Debugf(ctx, "Handling request for endpoint for schema: %s", endpoint)
	domain := strings.ToLower(cxtDomain)
	domain = strings.ReplaceAll(domain, ":", "_")

	// Construct the schema file name.
	schemaFileName := fmt.Sprintf("%s_%s_%s", domain, version, endpoint)
	schema, err := v.getCompiledSchema(schemaFileName)
	if err != nil {
		if errors.Is(err, errSchemaKeyNotFound) {
			return model.NewBadReqErr(fmt.Errorf("schema not found for domain: %s", domain))
		}
		return model.NewBadReqErr(err)
	}

	var jsonData any
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return model.NewBadReqErr(fmt.Errorf("failed to parse JSON data: %v", err))
	}
	err = schema.Validate(jsonData)
	if err != nil {
		// Handle schema validation errors
		if validationErr, ok := err.(*jsonschema.ValidationError); ok {
			// Convert validation errors into an array of SchemaValError
			var schemaErrors []model.Error
			for _, cause := range validationErr.Causes {
				// Extract the path and message from the validation error
				path := strings.Join(cause.InstanceLocation, ".") // JSON path to the invalid field
				message := cause.Error()                          // Validation error message

				// Append the error to the schemaErrors array
				schemaErrors = append(schemaErrors, model.Error{
					Paths:   path,
					Message: message,
				})
			}
			// Return the array of schema validation errors
			return &model.SchemaValidationErr{Errors: schemaErrors}
		}
		return fmt.Errorf("validation failed: %v", err)
	}

	// Return nil if validation succeeds
	return nil
}

func (v *schemaValidator) getCompiledSchema(schemaKey string) (*jsonschema.Schema, error) {
	v.cacheMu.RLock()
	if schema, ok := v.schemaCache[schemaKey]; ok {
		v.cacheMu.RUnlock()
		return schema, nil
	}
	schemaPath, ok := v.schemaFiles[schemaKey]
	v.cacheMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", errSchemaKeyNotFound, schemaKey)
	}

	// Serialize first-time compiles to avoid concurrent compiler use and duplicate work.
	v.compileMu.Lock()
	defer v.compileMu.Unlock()

	v.cacheMu.RLock()
	if schema, ok := v.schemaCache[schemaKey]; ok {
		v.cacheMu.RUnlock()
		return schema, nil
	}
	v.cacheMu.RUnlock()

	compiledSchema, err := v.compiler.Compile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compile JSON schema from file %s: %w", filepath.Base(schemaPath), err)
	}

	v.cacheMu.Lock()
	v.schemaCache[schemaKey] = compiledSchema
	v.cacheMu.Unlock()
	return compiledSchema, nil
}

// Initialise initialises the validator provider by indexing all JSON schema files
// from the specified directory for lazy compilation on first use.
func (v *schemaValidator) initialise() error {
	schemaDir := v.config.SchemaDir
	// Check if the directory exists and is accessible.
	info, err := os.Stat(schemaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("schema directory does not exist: %s", schemaDir)
		}
		return fmt.Errorf("failed to access schema directory: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("provided schema path is not a directory: %s", schemaDir)
	}

	// Helper function to process directories recursively.
	var processDir func(dir string) error
	processDir = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("failed to read directory: %v", err)
		}

		for _, entry := range entries {
			entryPath := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				// Recursively process subdirectories.
				if err := processDir(entryPath); err != nil {
					return err
				}
			} else if filepath.Ext(entry.Name()) == ".json" {
				// Use relative path from schemaDir to avoid absolute paths and make schema keys domain/version specific.
				relativePath, err := filepath.Rel(schemaDir, entryPath)
				if err != nil {
					return fmt.Errorf("failed to get relative path for file %s: %v", entry.Name(), err)
				}
				// Split the relative path to get domain, version, and schema.
				parts := strings.Split(relativePath, string(os.PathSeparator))

				// Ensure that the file path has at least 3 parts: domain, version, and schema file.
				if len(parts) < 3 {
					return fmt.Errorf("invalid schema file structure, expected domain/version/schema.json but got: %s", relativePath)
				}

				// Extract domain, version, and schema filename from the parts.
				// Validate that the extracted parts are non-empty.
				domain := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(parts[1])
				schemaFileName := strings.TrimSpace(parts[2])
				schemaFileName = strings.TrimSuffix(schemaFileName, ".json")

				if domain == "" || version == "" || schemaFileName == "" {
					return fmt.Errorf("invalid schema file structure, one or more components are empty. Relative path: %s", relativePath)
				}

				// Construct a unique key combining domain, version, and schema name (e.g., ondc_trv10_v2.0.0_schema).
				uniqueKey := fmt.Sprintf("%s_%s_%s", domain, version, schemaFileName)
				// Store schema path for lazy compilation on first use.
				v.schemaFiles[uniqueKey] = entryPath
			}
		}
		return nil
	}

	// Start processing from the root schema directory.
	if err := processDir(schemaDir); err != nil {
		return fmt.Errorf("failed to read schema directory: %v", err)
	}

	return nil
}
