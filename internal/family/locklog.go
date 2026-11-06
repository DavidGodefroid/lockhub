package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A locklog console reads host logs: the directories its profile names,
// bound read-only and non-recursive at their own paths. Its image derives
// the mount plan from the profile (`locklog mounts`); lox run runs that on
// the reviewed copy, checks every line on the host as locklog's own
// launcher does (scripts/locklog: read_plan, plan_line), and shows every
// line it derives in the review.

const (
	// LocklogPIIDir is where a locklog console keeps its PII rule sets
	// (LOCKLOG_PII_DIR): its home volume, never the read-only project.
	LocklogPIIDir = "/home/locklog/pii-rules"
	// LocklogMapTarget is where the console reads the containers map.
	LocklogMapTarget = "/run/locklog-map"
	// LocklogConsoleLabel marks a locklog console container: the map
	// never serves one (the console skips it whatever the map says).
	LocklogConsoleLabel = "locklog.console"
	// agentAccount is the image's agent (10052, in locklog-clients):
	// locklog mounts runs as it, with no network, as under the launcher.
	agentAccount = "10052:10050"
	// mapFormat heads a containers map version.
	mapFormat = "locklog-map 1"
	// maxPlan bounds the output of locklog mounts.
	maxPlan = 64 << 10
)

// DefaultLogRoots are the directories a log directory may be bound from
// (the launcher's built-in allowlist).
var DefaultLogRoots = []string{"/var/log", "/run/log/journal"}

// JournalDirs are the journal's directories (a journald line binds those
// the host has).
var JournalDirs = []string{"/var/log/journal", "/run/log/journal"}

// logGroups are the only groups the console may join to read logs; gid 0
// only for the Docker containers root.
var logGroups = []string{"adm", "systemd-journal"}

// LogHost is what lox run checks a mount plan against: the host's log
// roots, journal directories and group names (nil fields: the host's).
type LogHost struct {
	Roots     []string
	Journals  []string
	GroupName func(gid uint32) string
	// GOOS is runtime.GOOS ("" for it).
	GOOS string
}

func (h *LogHost) roots() []string {
	if h != nil && h.Roots != nil {
		return h.Roots
	}
	return DefaultLogRoots
}

func (h *LogHost) journals() []string {
	if h != nil && h.Journals != nil {
		return h.Journals
	}
	return JournalDirs
}

func (h *LogHost) groupName(gid uint32) string {
	if h != nil && h.GroupName != nil {
		return h.GroupName(gid)
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return ""
	}
	return g.Name
}

func (h *LogHost) goos() string {
	if h != nil && h.GOOS != "" {
		return h.GOOS
	}
	return runtime.GOOS
}

// LogPlan is a locklog instance's mount plan as lox run checked it on the
// host: what its console service mounts and joins.
type LogPlan struct {
	Profile    string `json:"profile"`
	Production bool   `json:"production"`
	// Lines are locklog mounts' lines, as printed.
	Lines []string `json:"lines"`
	// Binds are the host directories bound read-only and non-recursive at
	// their own paths, in plan order.
	Binds []string `json:"binds,omitempty"`
	// Expect is LOCKLOG_EXPECT_ROOTS: "dev:inode path;" per bind lox run
	// could stat (the console checks its mount points against them).
	Expect string `json:"expect,omitempty"`
	// GIDs are the supplementary groups (group_add), sorted.
	GIDs []uint32 `json:"gids,omitempty"`
	// DockerRoot is the containers root of a docker source
	// (LOCKLOG_DOCKER_ROOT); DockerGlobs its approved name globs.
	DockerRoot  string   `json:"docker_root,omitempty"`
	DockerGlobs []string `json:"docker_globs,omitempty"`
	// MapDir is the containers map's host directory (docker sources).
	MapDir string `json:"map_dir,omitempty"`
	// Remote: the profile reads a remote source (Loki, Elasticsearch,
	// OpenSearch).
	Remote bool `json:"remote,omitempty"`
	// Warnings are files or directories the console will not reach.
	Warnings []string `json:"-"`
	notes    map[string]string
}

// Review is the plan's lines in lox run's review, for instance n.
func (p *LogPlan) Review(n string) []string {
	pre := "lock " + n + " "
	s := []string{fmt.Sprintf("%smount plan of profile %s (production %t), from locklog mounts on the reviewed copy", pre, p.Profile, p.Production)}
	for _, l := range p.Lines {
		s = append(s, pre+"plan "+l)
	}
	for _, b := range p.Binds {
		s = append(s, fmt.Sprintf("%sbind %s (read-only, non-recursive%s)", pre, b, p.notes[b]))
	}
	if len(p.GIDs) > 0 {
		g := make([]string, len(p.GIDs))
		for i, x := range p.GIDs {
			g[i] = strconv.FormatUint(uint64(x), 10)
		}
		s = append(s, pre+"groups "+strings.Join(g, " "))
	}
	if p.MapDir != "" {
		s = append(s, fmt.Sprintf("%scontainers map %s at %s (read-only): written by lox run and lox refresh %s, not while the console runs", pre, p.MapDir, LocklogMapTarget, n))
	}
	return s
}

var planHeader = regexp.MustCompile(`^profile ([A-Za-z0-9][A-Za-z0-9_.-]{0,63}) (true|false)$`)

// mountSafe is the launcher's safe: none of the characters a mount spec
// or LOCKLOG_EXPECT_ROOTS cannot carry.
func mountSafe(s string) bool {
	if strings.ContainsAny(s, ",=:;\"'`\\\n") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// physical: d is a directory whose real path is itself (no link on its
// path, no "..").
func physical(d string) bool {
	fi, err := os.Lstat(d)
	if err != nil || !fi.IsDir() || filepath.Clean(d) != d {
		return false
	}
	r, err := filepath.EvalSymlinks(d)
	return err == nil && r == d
}

func statOf(p string) (*syscall.Stat_t, os.FileMode, bool) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return st, fi.Mode(), ok
}

func devIno(p string) (string, bool) {
	st, _, ok := statOf(p)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10), true
}

// planner fills a LogPlan from locklog mounts' lines (plan_line).
type planner struct {
	h     *LogHost
	p     *LogPlan
	local bool
}

func (pl *planner) addGID(g uint32) {
	if !slices.Contains(pl.p.GIDs, g) {
		pl.p.GIDs = append(pl.p.GIDs, g)
	}
}

func (pl *planner) bind(d, note string) {
	if slices.Contains(pl.p.Binds, d) {
		return
	}
	pl.p.Binds = append(pl.p.Binds, d)
	if di, ok := devIno(d); ok {
		pl.p.Expect += di + " " + d + ";"
	} else {
		note += "; owned by root: not checked from the host"
	}
	if note != "" {
		if pl.p.notes == nil {
			pl.p.notes = map[string]string{}
		}
		pl.p.notes[d] = note
	}
}

func (pl *planner) allowed(gid uint32) bool { return slices.Contains(logGroups, pl.h.groupName(gid)) }

// reach: the gid the console needs to list dir (file ""), or to search
// dir and read file, when an allowed group grants it; nothing when the
// others' bits do; a warning otherwise.
func (pl *planner) reach(dir, file string) {
	dst, dm, ok := statOf(dir)
	if !ok {
		return
	}
	if file == "" {
		if dm.Perm()&0o005 == 0o005 {
			return
		}
		if pl.allowed(dst.Gid) && dm.Perm()&0o050 == 0o050 {
			pl.addGID(dst.Gid)
			return
		}
		pl.p.Warnings = append(pl.p.Warnings, fmt.Sprintf("the console cannot list %s (its group is not one it may join: %s)", dir, strings.Join(logGroups, ", ")))
		return
	}
	fst, fm, ok := statOf(file)
	if !ok {
		return
	}
	if dm.Perm()&0o001 != 0 && fm.Perm()&0o004 != 0 {
		return
	}
	if pl.allowed(fst.Gid) && fm.Perm()&0o040 != 0 && (dm.Perm()&0o001 != 0 || (dst.Gid == fst.Gid && dm.Perm()&0o010 != 0)) {
		pl.addGID(fst.Gid)
		return
	}
	pl.p.Warnings = append(pl.p.Warnings, fmt.Sprintf("the console cannot read %s (its group is not one it may join: %s)", file, strings.Join(logGroups, ", ")))
}

func (pl *planner) underRoot(d string) bool {
	for _, r := range pl.h.roots() {
		if d == r || strings.HasPrefix(d, r+"/") {
			return true
		}
	}
	return false
}

var dockerGlob = regexp.MustCompile(`^[A-Za-z0-9_.*?][A-Za-z0-9_.*?-]*$`)

func (pl *planner) line(l string) error {
	f := strings.Split(l, " ")
	switch f[0] {
	case "file":
		if len(f) != 3 {
			return fmt.Errorf("malformed line: %s", l)
		}
		pl.local = true
		dir, glob := f[1], f[2]
		switch {
		case !mountSafe(dir) || !mountSafe(glob):
			return fmt.Errorf("%s holds a character a mount cannot carry", dir)
		case dir == "/":
			return errors.New("/ cannot be bound")
		case !strings.HasPrefix(dir, "/"):
			return fmt.Errorf("%s is not absolute", dir)
		case !strings.HasPrefix(glob, dir+"/"):
			return fmt.Errorf("%s is not under %s", glob, dir)
		case strings.Contains(glob+"/", "//") || strings.Contains(glob+"/", "/./") || strings.Contains(glob+"/", "/../"):
			return fmt.Errorf("%s is not a clean path", glob)
		case !physical(dir):
			return fmt.Errorf("%s is not a directory with no symbolic link on its path", dir)
		case !pl.underRoot(dir):
			return fmt.Errorf("%s is not under an allowed log root (%s)", dir, strings.Join(pl.h.roots(), " "))
		}
		pl.bind(dir, "")
		pl.reach(dir, "")
		if !strings.Contains(glob, "**") {
			ms, _ := filepath.Glob(glob)
			for _, m := range ms {
				if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() {
					pl.reach(filepath.Dir(m), m)
				}
			}
		}
	case "docker":
		if len(f) != 2 || !dockerGlob.MatchString(f[1]) {
			return fmt.Errorf("invalid container glob: %s", l)
		}
		if !slices.Contains(pl.p.DockerGlobs, f[1]) {
			pl.p.DockerGlobs = append(pl.p.DockerGlobs, f[1])
		}
	case "journald":
		if len(f) != 1 {
			return fmt.Errorf("malformed line: %s", l)
		}
		pl.local = true
		found := false
		for _, j := range pl.h.journals() {
			if !physical(j) {
				continue
			}
			found = true
			pl.bind(j, "")
			pl.reach(j, "")
		}
		if !found {
			pl.p.Warnings = append(pl.p.Warnings, "no journal directory ("+strings.Join(pl.h.journals(), ", ")+") on this host")
		}
	case "remote":
		if len(f) != 1 {
			return fmt.Errorf("malformed line: %s", l)
		}
		pl.p.Remote = true
	default:
		return fmt.Errorf("unknown line: %s", l)
	}
	return nil
}

// errDockerAlone is the launcher's refusal of a docker source beside
// file or journald sources.
var errDockerAlone = errors.New("a docker source cannot share a console with file or journald sources: the containers root is read with group 0, which would apply to every bound log directory; put the container logs in a profile of their own and a lock of their own")

// DeriveLogPlan checks the output of locklog mounts on the host, as the
// launcher does, and returns the plan. mapDir is the containers map's
// directory (used for a docker source).
func DeriveLogPlan(ctx context.Context, run Runner, h *LogHost, out []byte, mapDir string) (*LogPlan, error) {
	if len(out) > maxPlan {
		return nil, errors.New("mount plan: too long")
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	m := planHeader.FindStringSubmatch(lines[0])
	if m == nil {
		return nil, errors.New("mount plan: malformed header")
	}
	p := &LogPlan{Profile: m[1], Production: m[2] == "true"}
	pl := &planner{h: h, p: p}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if err := pl.line(l); err != nil {
			return nil, fmt.Errorf("mount plan: %w", err)
		}
		p.Lines = append(p.Lines, l)
	}
	if pl.local || len(p.DockerGlobs) > 0 {
		if h.goos() == "darwin" {
			return nil, errors.New("local log sources are not supported with Docker Desktop on macOS (the containers' logs live in its VM); use a remote source")
		}
		if o, err := run.Run(ctx, nil, "docker", "info", "--format", "{{.SecurityOptions}}"); err == nil && strings.Contains(string(o), "rootless") {
			return nil, errors.New("rootless Docker is not supported for local log sources: its containers' logs and the host's journal are out of the console's reach")
		}
	}
	if len(p.DockerGlobs) > 0 {
		if pl.local || len(p.Binds) > 0 || len(p.GIDs) > 0 {
			return nil, errDockerAlone
		}
		o, err := run.Run(ctx, nil, "docker", "info", "--format", "{{.DockerRootDir}}")
		if err != nil {
			return nil, fmt.Errorf("the Docker root directory (docker info): %w", err)
		}
		dr := strings.TrimSpace(string(o))
		r := strings.TrimSuffix(dr, "/") + "/containers"
		switch {
		case !strings.HasPrefix(r, "/") || r == "/containers":
			return nil, fmt.Errorf("the Docker root directory %q is not an absolute path", dr)
		case path.Clean(r) != r:
			return nil, fmt.Errorf("the Docker root directory %s is not a clean path", dr)
		case strings.ContainsAny(r, "*?[ ") || !mountSafe(r):
			return nil, fmt.Errorf("the Docker root directory %s holds a character a mount cannot carry", dr)
		case !mountSafe(mapDir) || strings.Contains(mapDir, " "):
			return nil, fmt.Errorf("%s holds a character a mount cannot carry", mapDir)
		}
		p.DockerRoot, p.MapDir = r, mapDir
		pl.bind(r, "; the Docker containers root, group 0 for it only")
		pl.addGID(0)
	}
	slices.Sort(p.GIDs)
	return p, nil
}

// logDir is a locklog instance's host state (0700): its applied plan and
// its containers map directory.
func logDir(state, inst string) string { return filepath.Join(state, "locklog", inst) }

// LogMapDir is the containers map directory of a locklog instance.
func LogMapDir(state, inst string) string { return filepath.Join(logDir(state, inst), "map") }

const planFile = "plan.json"

// writeLogPlan keeps the applied plan (lox refresh and lox doctor read
// it), host only.
func writeLogPlan(state, inst string, p *LogPlan) error {
	for _, d := range []string{filepath.Join(state, "locklog"), logDir(state, inst)} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return writeAtomic(filepath.Join(logDir(state, inst), planFile), append(b, '\n'), 0o600)
}

// ReadLogPlan is the plan the last confirmed lox run applied to inst.
func ReadLogPlan(state, inst string) (*LogPlan, error) {
	if err := checkPrivate(logDir(state, inst)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(logDir(state, inst), planFile))
	if err != nil {
		return nil, err
	}
	var p LogPlan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", planFile, err)
	}
	return &p, nil
}

// LogMap is one snapshot of the containers map.
type LogMap struct {
	Content                 string
	Mapped, Excluded, Skips int
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func isHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func globMatch(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// BuildLogMap is the map of the containers the approved globs name, as
// the launcher's write_map: "c <id> <name> <max-file> <compress>" per
// json-file container, "x <id>" per console container (by label or name)
// or record that does not parse. Names and ids only, sorted.
func BuildLogMap(ctx context.Context, run Runner, globs []string) (LogMap, error) {
	out, err := run.Run(ctx, nil, "docker", "ps", "-a", "-q", "--no-trunc")
	if err != nil {
		return LogMap{}, fmt.Errorf("docker ps: %w", err)
	}
	var ids, dups []string
	for _, id := range strings.Split(string(out), "\n") {
		if !isHexID(id) {
			continue
		}
		if slices.Contains(ids, id) {
			dups = append(dups, id)
			continue
		}
		ids = append(ids, id)
	}
	type rec struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			LogConfig struct {
				Type   string            `json:"Type"`
				Config map[string]string `json:"Config"`
			} `json:"LogConfig"`
		} `json:"HostConfig"`
	}
	var m LogMap
	var cs []string
	xs := map[string]bool{}
	names := map[string][]string{}
	for _, id := range ids {
		if slices.Contains(dups, id) {
			xs[id] = true
			continue
		}
		b, err := run.Run(ctx, nil, "docker", "inspect", "--type", "container", "--format", "{{json .}}", id)
		if err != nil {
			continue // gone since the listing
		}
		var r rec
		bad := json.Unmarshal(b, &r) != nil || r.ID != id
		name := strings.TrimPrefix(r.Name, "/")
		if bad || !validName.MatchString(name) {
			xs[id] = true
			m.Skips++
			continue
		}
		if r.Config.Labels[LocklogConsoleLabel] != "" || strings.HasPrefix(name, "locklog-console") {
			xs[id] = true
			continue
		}
		if !globMatch(globs, name) {
			continue
		}
		if r.HostConfig.LogConfig.Type != "json-file" {
			m.Skips++
			continue
		}
		mf := 1
		if v, ok := r.HostConfig.LogConfig.Config["max-file"]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || strings.HasPrefix(v, "-") || strings.HasPrefix(v, "+") {
				m.Skips++
				continue
			}
			mf = min(max(n, 1), 100)
		}
		cmp := "0"
		switch r.HostConfig.LogConfig.Config["compress"] {
		case "true":
			cmp = "1"
		case "false", "":
		default:
			m.Skips++
			continue
		}
		names[name] = append(names[name], id)
		cs = append(cs, fmt.Sprintf("c %s %s %d %s", id, name, mf, cmp))
	}
	// A name given to two ids in one snapshot: neither is mapped.
	cs = slices.DeleteFunc(cs, func(l string) bool {
		f := strings.Fields(l)
		if len(names[f[2]]) > 1 {
			xs[f[1]] = true
			return true
		}
		return false
	})
	slices.Sort(cs)
	var b strings.Builder
	b.WriteString(mapFormat + "\n")
	for _, l := range cs {
		b.WriteString(l + "\n")
	}
	xl := make([]string, 0, len(xs))
	for id := range xs {
		xl = append(xl, id)
	}
	slices.Sort(xl)
	for _, id := range xl {
		b.WriteString("x " + id + "\n")
	}
	m.Content, m.Mapped, m.Excluded = b.String(), len(cs), len(xl)
	return m, nil
}

var mapVersion = regexp.MustCompile(`^map\.v([1-9][0-9]{0,14})$`)

// mapVersions are dir's map versions, newest first.
func mapVersions(dir string) []int {
	ents, _ := os.ReadDir(dir)
	var vs []int
	for _, e := range ents {
		if m := mapVersion.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			n, _ := strconv.Atoi(m[1])
			vs = append(vs, n)
		}
	}
	slices.Sort(vs)
	slices.Reverse(vs)
	return vs
}

// ensureMapDir makes dir the map directory: yours, 0755, not a link (the
// console reads it through a read-only bind; its parents stay 0700).
func ensureMapDir(dir string) error {
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory (a link?)", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, not by you", dir, st.Uid)
	}
	return os.Chmod(dir, 0o755)
}

// mapLockTries and mapLockWait bound the wait for another writer of a
// map (tests shorten them); a lock older than mapLockStale is a killed
// writer's, taken over.
var (
	mapLockTries = 100
	mapLockWait  = 100 * time.Millisecond
	mapLockStale = time.Minute
)

// WriteLogMap writes m as the next version of the map in dir, atomically
// and under the directory's writer lock, keeping the last two versions.
func WriteLogMap(dir string, m LogMap) (int, error) {
	if err := ensureMapDir(dir); err != nil {
		return 0, err
	}
	lock := filepath.Join(dir, ".lock")
	for i := 0; ; i++ {
		if err := os.Mkdir(lock, 0o700); err == nil {
			break
		}
		if fi, err := os.Lstat(lock); err == nil && time.Since(fi.ModTime()) > mapLockStale {
			os.Remove(lock)
			continue
		}
		if i >= mapLockTries {
			return 0, fmt.Errorf("%s: another writer holds the map", lock)
		}
		time.Sleep(mapLockWait)
	}
	defer os.Remove(lock)
	// Temporary files a killed writer left behind.
	if tmps, _ := filepath.Glob(filepath.Join(dir, ".map.tmp.*")); len(tmps) > 0 {
		for _, t := range tmps {
			if fi, err := os.Lstat(t); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > mapLockStale {
				os.Remove(t)
			}
		}
	}
	n := 1
	if vs := mapVersions(dir); len(vs) > 0 {
		n = vs[0] + 1
	}
	f, err := os.CreateTemp(dir, ".map.tmp.")
	if err != nil {
		return 0, err
	}
	_, err = f.WriteString(m.Content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, fmt.Sprintf("map.v%d", n)))
	}
	if err != nil {
		os.Remove(f.Name())
		return 0, err
	}
	for _, v := range mapVersions(dir) {
		if v < n-1 {
			os.Remove(filepath.Join(dir, fmt.Sprintf("map.v%d", v)))
		}
	}
	return n, nil
}

// newestLogMap is the content of dir's newest map version, and its N
// (0: none).
func newestLogMap(dir string) (string, int, error) {
	vs := mapVersions(dir)
	if len(vs) == 0 {
		return "", 0, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("map.v%d", vs[0])))
	return string(b), vs[0], err
}

// updateLogMap writes a new version of p's map when the containers its
// globs name changed since the newest one: lox run, once the consoles it
// created exist (they are excluded from then on). It returns the newest
// version and whether it wrote it.
func updateLogMap(ctx context.Context, run Runner, p *LogPlan) (int, bool, error) {
	m, err := BuildLogMap(ctx, run, p.DockerGlobs)
	if err != nil {
		return 0, false, err
	}
	have, v, err := newestLogMap(p.MapDir)
	if err != nil {
		return 0, false, err
	}
	if v > 0 && have == m.Content {
		return v, false, nil
	}
	v, err = WriteLogMap(p.MapDir, m)
	return v, err == nil, err
}

// logPlanLine is a review line a mount plan derives (LogPlan.Review):
// from the profile, not from lockfamily.yaml.
var logPlanLine = regexp.MustCompile(`^lock \S+ (mount plan of profile|plan|bind|groups|containers map) `)

// Refresh is `lox refresh <instance>`: it rewrites the containers map of
// a locklog lock once, from the approved globs of the plan the last
// confirmed lox run applied (the running console re-reads it).
func Refresh(ctx context.Context, run Runner, state string, c *Config, inst string) (string, error) {
	l, ok := c.Locks[inst]
	if !ok {
		return "", fmt.Errorf("no lock %q", inst)
	}
	if !Kinds[l.Type].Mounts {
		return "", fmt.Errorf("lock %s is a %s lock: only a locklog lock has a containers map", inst, l.Type)
	}
	p, err := ReadLogPlan(state, inst)
	if err != nil {
		return "", fmt.Errorf("the plan lox run applied to %s: %w (run lox run first)", inst, err)
	}
	if len(p.DockerGlobs) == 0 {
		return "", fmt.Errorf("lock %s's profile has no docker source: there is no containers map to write", inst)
	}
	m, err := BuildLogMap(ctx, run, p.DockerGlobs)
	if err != nil {
		return "", err
	}
	dir := LogMapDir(state, inst)
	v, err := WriteLogMap(dir, m)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("containers map v%d of %s (%s): %d mapped, %d console containers excluded, %d skipped (not json-file, or not a valid name)", v, inst, dir, m.Mapped, m.Excluded, m.Skips), nil
}

// logMapStale is lox doctor's check of a docker source's map: the newest
// version against the containers the approved globs name now.
// It returns "" when the plan has no docker source.
func logMapStale(ctx context.Context, run Runner, state, inst string) (msg string, stale bool, err error) {
	p, err := ReadLogPlan(state, inst)
	if err != nil {
		return "", false, fmt.Errorf("the plan lox run applied: %w (run lox run first)", err)
	}
	if len(p.DockerGlobs) == 0 {
		return "", false, nil
	}
	dir := LogMapDir(state, inst)
	have, v, err := newestLogMap(dir)
	if err != nil {
		return "", false, err
	}
	if v == 0 {
		return "", false, fmt.Errorf("no containers map in %s: run lox refresh %s", dir, inst)
	}
	m, err := BuildLogMap(ctx, run, p.DockerGlobs)
	if err != nil {
		return "", false, err
	}
	if have != m.Content {
		return fmt.Sprintf("map.v%d is stale: containers its globs name were created, removed or renamed since (run lox refresh %s)", v, inst), true, nil
	}
	return fmt.Sprintf("map.v%d current: %d mapped", v, m.Mapped), false, nil
}
