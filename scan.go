package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/structs"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "diec"
	category = "exe"

	// diecPath is the prebuilt Detect-It-Easy v3.21 CLI baked into the image
	// (the `diec` command-line detector — headless, no GUI). diecLibs is the
	// directory holding the bundled Qt5 shared libraries diec is linked against.
	diecPath = "/opt/die/base/diec"
	diecLibs = "/opt/die/base"

	// maxEntropyRecords caps the per-section entropy records stored in the doc
	// so a binary with many sections cannot bloat the ES document.
	maxEntropyRecords = 1000
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string
	// es is the elasticsearch database object
	es elasticsearch.Database
)

// jsonFloat is a float64 that always marshals with a decimal point. Go's
// encoding/json renders a whole-number float64 (e.g. 0) as a bare integer
// ("0"), which Elasticsearch maps as a `long`; a later non-whole value in the
// same field ("2.66") is a `float`, and ES rejects the type change. Forcing a
// decimal keeps every entropy value a consistent ES float.
type jsonFloat float64

// MarshalJSON renders the value with six decimal places (plenty for entropy).
func (f jsonFloat) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%.6f", float64(f))), nil
}

// resultsData is the shape the diec engine writes to plugins.exe.diec.
//
// diec is a NEW engine (there is no classic malice/diec plugin to preserve), so
// this shape follows the `exe`-category convention established by pescan/floss/
// office: a top-level summary (filetype, found, packed, packers, status), the
// curated diec JSON data (values, info, entropy), and a human-readable markdown
// summary.
type resultsData struct {
	// Filetype is the primary identified file type (e.g. "ELF64", "PE32+",
	// "Mach-O 64-bit"). Empty when diec could not identify the file.
	Filetype string `json:"filetype,omitempty" structs:"filetype,omitempty"`
	// Found reports whether diec identified the file (at least one detect).
	Found bool `json:"found" structs:"found"`
	// Status is "ok" on success or a short error/no-match description.
	Status string `json:"status" structs:"status"`
	// Packed is true when a packer/protector signature matched.
	Packed bool `json:"packed" structs:"packed"`
	// Packagers lists the packer/protector names that matched.
	Packagers []string `json:"packers,omitempty" structs:"packers,omitempty"`
	// Values holds every detected value (compiler, library, packer, protector,
	// tool, ...) across all detects.
	Values []diecValue `json:"values,omitempty" structs:"values,omitempty"`
	// Info is the file metadata from `diec --json -i` (architecture, endianness,
	// MIME, ...). Empty when unavailable.
	Info map[string]string `json:"info,omitempty" structs:"info,omitempty"`
	// Entropy is the per-section entropy from `diec --json -e` (curated).
	Entropy *diecEntropy `json:"entropy,omitempty" structs:"entropy,omitempty"`
	// MarkDown is the human-readable summary rendered by the malice UI.
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// diecValue is a single detected value (detects[].values[]).
type diecValue struct {
	Name    string `json:"name" structs:"name"`
	Type    string `json:"type" structs:"type"`
	Version string `json:"version,omitempty" structs:"version,omitempty"`
	String  string `json:"string,omitempty" structs:"string,omitempty"`
	Info    string `json:"info,omitempty" structs:"info,omitempty"`
}

// diecEntropy is the curated entropy summary.
type diecEntropy struct {
	Max     jsonFloat        `json:"max" structs:"max"`
	Packed  bool             `json:"packed" structs:"packed"`
	Records []diecEntropyRec `json:"records,omitempty" structs:"records,omitempty"`
}

// diecEntropyRec is a single per-section entropy record (records[]).
type diecEntropyRec struct {
	Entropy jsonFloat `json:"entropy" structs:"entropy"`
	Name    string    `json:"name" structs:"name"`
	Offset  int       `json:"offset" structs:"offset"`
	Size    int       `json:"size" structs:"size"`
	Status  string    `json:"status" structs:"status"`
}

// diec wraps resultsData; the markdown template references .Results.*
type diec struct {
	Results resultsData `json:"diec,omitempty"`
}

// ---- diec --json schemas (Detect-It-Easy v3.21) ----
//
// `diec --json <file>`   -> {"detects": [{filetype, info, offset,
//                             parentfilepart, size, values: [{info, name,
//                             string, type, version}]}]}
// `diec --json -i <file>`-> {"data": {"Info": {Architecture, Endianness,
//                             Extension, File name, File type, MIME, Mode,
//                             Operation system, Size, String, Type}}}
// `diec --json -e <file>`-> {"records": [{entropy, name, offset, size, status}]}
//
// Only the fields the engine maps are declared; json.Unmarshal skips the rest.

type diecDetect struct {
	Filetype string      `json:"filetype"`
	Info     string      `json:"info"`
	Offset   string      `json:"offset"`
	Parent   string      `json:"parentfilepart"`
	Size     string      `json:"size"`
	Values   []diecValue `json:"values"`
}

type diecDetectsDoc struct {
	Detects []diecDetect `json:"detects"`
}

type diecInfoDoc struct {
	Data struct {
		Info map[string]string `json:"Info"`
	} `json:"data"`
}

type diecEntropyDoc struct {
	Records []diecEntropyRec `json:"records"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
		}).Fatal(err)
	}
}

// runDiec executes the diec CLI with the given args and returns its stdout.
//
// diec exits non-zero for files it cannot fully analyze but may still emit
// valid JSON on stdout, so callers inspect stdout even when err != nil. The
// bundled Qt5 libraries live in diecLibs; LD_LIBRARY_PATH is set so the binary
// resolves them without the diec.sh wrapper.
func runDiec(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, diecPath, args...)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+diecLibs)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), errors.Wrapf(err, "diec %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// isPackedStatus reports whether a diec entropy record status indicates packing.
// diec reports "not packed" for clean sections and "packed"/"possibly packed"
// (and similar) for suspicious ones.
func isPackedStatus(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	if l == "" || strings.Contains(l, "not packed") {
		return false
	}
	return strings.Contains(l, "packed")
}

// scanFile runs diec against path and returns the curated results.
//
// Three diec invocations are made (the -i and -e flags each replace the default
// detects output, so they cannot be combined into one call):
//
//  1. `diec --json -d -u <file>` — file type + values (deep + heuristic scan)
//  2. `diec --json -i <file>`    — file metadata
//  3. `diec --json -e <file>`    — per-section entropy
//
// The detects call is primary: on a total failure (no parseable JSON) the
// engine returns a found=false doc with an error status so the scan doc is
// still written. The info and entropy calls are best-effort and never fail the
// scan.
func scanFile(ctx context.Context, path string) resultsData {

	detectOut, detectErr := runDiec(ctx, "--json", "-d", "-u", path)
	infoOut, infoErr := runDiec(ctx, "--json", "-i", path)
	entOut, entErr := runDiec(ctx, "--json", "-e", path)

	results := resultsData{Status: "ok"}

	// 1. detects (primary)
	if detectErr != nil && strings.TrimSpace(detectOut) == "" {
		results.Found = false
		results.Status = "diec detect failed: " + detectErr.Error()
		return results
	}
	var detectDoc diecDetectsDoc
	if err := json.Unmarshal([]byte(detectOut), &detectDoc); err != nil {
		results.Found = false
		results.Status = "failed to parse diec detects JSON: " + err.Error()
		return results
	}
	for _, d := range detectDoc.Detects {
		if results.Filetype == "" && d.Filetype != "" {
			results.Filetype = d.Filetype
		}
		for _, v := range d.Values {
			results.Values = append(results.Values, diecValue{
				Name: v.Name, Type: v.Type, Version: v.Version, String: v.String, Info: v.Info,
			})
			if (v.Type == "packer" || v.Type == "protector") && v.Name != "" {
				results.Packed = true
				results.Packagers = append(results.Packagers, v.Name)
			}
		}
	}
	if len(detectDoc.Detects) > 0 {
		results.Found = true
	} else {
		results.Found = false
		results.Status = "no file type detected"
	}
	if len(results.Packagers) > 0 {
		results.Packagers = utils.RemoveDuplicates(results.Packagers)
	}

	// 2. info (best-effort)
	if infoErr == nil && strings.TrimSpace(infoOut) != "" {
		var infoDoc diecInfoDoc
		if err := json.Unmarshal([]byte(infoOut), &infoDoc); err == nil && len(infoDoc.Data.Info) > 0 {
			results.Info = infoDoc.Data.Info
		}
	}

	// 3. entropy (best-effort)
	if entErr == nil && strings.TrimSpace(entOut) != "" {
		var entDoc diecEntropyDoc
		if err := json.Unmarshal([]byte(entOut), &entDoc); err == nil && len(entDoc.Records) > 0 {
			ent := &diecEntropy{}
			for _, r := range entDoc.Records {
				if r.Entropy > ent.Max {
					ent.Max = r.Entropy
				}
				if isPackedStatus(r.Status) {
					ent.Packed = true
				}
			}
			if len(entDoc.Records) > maxEntropyRecords {
				ent.Records = entDoc.Records[:maxEntropyRecords]
			} else {
				ent.Records = entDoc.Records
			}
			results.Entropy = ent
		}
	}

	return results
}

func generateMarkDownTable(d diec) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("diec").Parse(tpl))

	if err := t.Execute(&tplOut, d); err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "diec"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice Detect-It-Easy Plugin (file type + packer/protector)"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  240,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.ArgsUsage = "FILE to scan with diec"
	app.Action = func(c *cli.Context) error {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if !c.Args().Present() {
			log.Fatal(fmt.Errorf("Please supply a file to scan with diec"))
		}

		path, err := filepath.Abs(c.Args().First())
		if err != nil {
			// Cannot resolve the path; still write a doc so the scan is recorded.
			return storeResults(c, resultsData{Found: false, Status: "failed to get path from args: " + err.Error()}, "")
		}

		exists := true
		if _, err := os.Stat(path); os.IsNotExist(err) {
			exists = false
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
		defer cancel()

		var results resultsData
		if !exists {
			results = resultsData{Found: false, Status: "input file does not exist"}
		} else {
			results = scanFile(ctx, path)
		}

		return storeResults(c, results, path)
	}

	err := app.Run(os.Args)
	assert(err)
}

// storeResults renders the markdown, writes the results to Elasticsearch (when
// a URL is configured), and prints the result (markdown with -t, JSON
// otherwise). It always writes the doc — even for found=false / error results —
// so a scan is never left unwritten.
func storeResults(c *cli.Context, results resultsData, path string) error {
	d := diec{Results: results}
	d.Results.MarkDown = generateMarkDownTable(d)

	// Compute the doc id. MALICE_SCANID is always set by the malice core; the
	// sha256 fallback is only valid when the file exists (GetSHA256 fatals on a
	// missing file).
	scanID := os.Getenv("MALICE_SCANID")
	if scanID == "" && path != "" {
		scanID = utils.GetSHA256(path)
	}

	if len(c.String("elasticsearch")) > 0 {
		if err := es.Init(); err != nil {
			return errors.Wrap(err, "failed to initialize elasticsearch")
		}
		if err := es.StorePluginResults(database.PluginResults{
			ID:       scanID,
			Name:     name,
			Category: category,
			Data:     structs.Map(d.Results),
		}); err != nil {
			return errors.Wrapf(err, "failed to index malice/%s results", name)
		}
	}

	if c.Bool("table") {
		fmt.Println(d.Results.MarkDown)
	} else {
		d.Results.MarkDown = ""
		out, err := json.Marshal(d)
		if err != nil {
			return errors.Wrap(err, "failed to marshal JSON")
		}
		fmt.Println(string(out))
	}
	return nil
}
