package ebpf

import (
	"bufio"
	gocontext "context"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"os"
	"path/filepath"
	"strings"
)

func (t *Tracee) packageLoadedRoutine(ctx gocontext.Context) error {
	pattern := "/var/lib/docker/overlay2/*/merged"

	// Find all matching directories
	paths, err := filepath.Glob(pattern)
	if err != nil {
		logger.Errorw("Error matching pattern:", "err", err)
		return err
	}
	logger.Infow("path", "paths", paths)

	for _, path := range paths {
		err := t.scanContainer(ctx, path)
		if err != nil {
			return err
		}
		logger.Infow("TODO: breaking after one container")
		break
	}

	return nil
}

func (t *Tracee) scanContainer(ctx gocontext.Context, prefix string) error {
	dpkgInfoDir := "/var/lib/dpkg/info"

	// Map to store file paths and their corresponding package names
	fileToPackageMap := make(map[string]string)

	dirEntries, err := os.ReadDir(prefix + dpkgInfoDir)
	if err != nil {
		fmt.Printf("Failed to read dpkg info directory: %v\n", err)
		return err
	}

	for _, entry := range dirEntries {
		if strings.HasSuffix(entry.Name(), ".md5sums") {
			// Extract the package name from the file name
			packageName := strings.TrimSuffix(entry.Name(), ".md5sums")

			// Open the .md5sums file
			md5sumsFilePath := filepath.Join(dpkgInfoDir, entry.Name())
			file, err := os.Open(md5sumsFilePath)
			if err != nil {
				fmt.Printf("Failed to open file %s: %v\n", md5sumsFilePath, err)
				continue
			}
			defer file.Close()

			// Read the file line by line
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "usr/share") || strings.HasSuffix(line, ".gz") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) == 2 {
					filePath := "/" + parts[1]
					fileToPackageMap[filePath] = packageName
				}
			}

			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading file %s: %v\n", md5sumsFilePath, err)
			}
		}
	}
	maxSize := 0
	for file, pkg := range fileToPackageMap {
		if len(file) > maxSize {
			maxSize = len(file)
		}
		fmt.Printf("%s -> %s\n", file, pkg)
	}
	fmt.Printf("amount of entries=%d, max_path_size=%d\n", len(fileToPackageMap), maxSize)

	return nil
}

////func init() {
////	analyzer.RegisterPostAnalyzer(analyzer.TypeDpkg, newDpkgAnalyzer)
////}
//
////type dpkgAnalyzer struct {
////	logger *log.Logger
////}
//
////func newDpkgAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
////	//return &dpkgAnalyzer{
////	//	//logger: log.WithPrefix("dpkg"),
////	//}, nil
////}
//
//const (
//	analyzerVersion = 5
//
//	statusFile    = "/var/lib/dpkg/status"
//	statusDir     = "/var/lib/dpkg/status.d/"
//	infoDir       = "info/"
//	availableFile = "/var/lib/dpkg/available"
//)
//
//var (
//	dpkgSrcCaptureRegexp      = regexp.MustCompile(`(?P<name>[^\s]*)( \((?P<version>.*)\))?`)
//	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
//)
//
//func (t *Tracee) packageLoadedRoutine(ctx gocontext.Context) error {
//	pattern := "/var/lib/docker/overlay2/*/merged"
//
//	// Find all matching directories
//	paths, err := filepath.Glob(pattern)
//	if err != nil {
//		logger.Errorw("Error matching pattern:", "err", err)
//		return err
//	}
//	logger.Infow("path", "paths", paths)
//
//	for _, path := range paths {
//		err := t.scanContainer(ctx, path)
//		if err != nil {
//			return err
//		}
//		logger.Infow("TODO: breaking after one container")
//		break
//	}
//
//	return nil
//}
//
//func (t *Tracee) scanContainer(ctx gocontext.Context, prefix string) error {
//	var systemInstalledFiles []string
//	var packageInfos []types.PackageInfo
//
//	// parse `available` file to get digest for packages
//	//digests, err := t.parseDpkgAvailable(prefix)
//	//if err != nil {
//	//	logger.Infow("Unable to parse the available file", "path", log.FilePath(availableFile), "err", err)
//	//}
//
//	required := func(path string, d fs.DirEntry) bool {
//		return path != "available"
//	}
//
//	packageFiles := make(map[string][]string)
//
//	// parse other files
//	err := fsutils.WalkDir(os.DirFS(prefix+"/var/lib/dpkg"), ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
//		// parse list files
//		if t.isListFile(filepath.Split(path)) {
//			logger.Infow("inside list file")
//			scanner := bufio.NewScanner(r)
//			systemFiles, err := t.parseDpkgInfoList(scanner)
//			if err != nil {
//				return err
//			}
//			logger.Infow("a", "systemFiles", systemFiles)
//			packageFiles[strings.TrimSuffix(filepath.Base(path), ".list")] = systemFiles
//			systemInstalledFiles = append(systemInstalledFiles, systemFiles...)
//			return nil
//		}
//
//		return nil
//	})
//	if err != nil {
//		return xerrors.Errorf("dpkg walk error: %w", err)
//	}
//
//	// map the packages to their respective files
//	//for i, pkgInfo := range packageInfos {
//	//	for j, pkg := range pkgInfo.Packages {
//	//		installedFiles, found := packageFiles[pkg.Name]
//	//		if !found {
//	//			installedFiles = packageFiles[pkg.Name+":"+pkg.Arch]
//	//		}
//	//		packageInfos[i].Packages[j].InstalledFiles = installedFiles
//	//	}
//	//}
//
//	//logger.Infow("a", "packageInfos", packageInfos)
//	//logger.Infow("a", "systemInstalledFiles", systemInstalledFiles)
//
//	//TODO fill ebpf map
//	//return &analyzer.AnalysisResult{
//	//	PackageInfos:         packageInfos,
//	//	SystemInstalledFiles: systemInstalledFiles,
//	//}, nil
//
//	return nil
//
//}
//
//// parseDpkgInfoList parses /var/lib/dpkg/info/*.list
//func (t *Tracee) parseDpkgInfoList(scanner *bufio.Scanner) ([]string, error) {
//	var (
//		allLines       []string
//		installedFiles []string
//		previous       string
//	)
//
//	for scanner.Scan() {
//		current := scanner.Text()
//		if current == "/." {
//			continue
//		}
//		allLines = append(allLines, current)
//	}
//
//	if err := scanner.Err(); err != nil {
//		return nil, xerrors.Errorf("scan error: %w", err)
//	}
//
//	// Add the file if it is not directory.
//	// e.g.
//	//  /usr/sbin
//	//  /usr/sbin/tarcat
//	//
//	// In the above case, we should take only /usr/sbin/tarcat since /usr/sbin is a directory
//	// sort first,see here:https://github.com/aquasecurity/trivy/discussions/6543
//	sort.Strings(allLines)
//	for _, current := range allLines {
//		if !strings.HasPrefix(current, previous+"/") {
//			installedFiles = append(installedFiles, previous)
//		}
//		previous = current
//	}
//
//	// // Add the last file
//	if previous != "" && !strings.HasSuffix(previous, "/") {
//		installedFiles = append(installedFiles, previous)
//	}
//
//	return installedFiles, nil
//}
//
//// parseDpkgAvailable parses /var/lib/dpkg/available
//func (t *Tracee) parseDpkgAvailable(prefix string) (map[string]digest.Digest, error) {
//	f, err := os.Open(prefix + availableFile)
//	if err != nil {
//		return nil, xerrors.Errorf("file open error: %w", err)
//	}
//	defer f.Close()
//
//	pkgs := make(map[string]digest.Digest)
//	scanner := NewScanner(f)
//	for scanner.Scan() {
//		header, err := scanner.Header()
//		if !errors.Is(err, io.EOF) && err != nil {
//			logger.Debugw("Parse error", "path", availableFile, "err", err)
//			continue
//		}
//		name, version, checksum := header.Get("Package"), header.Get("Version"), header.Get("SHA256")
//		pkgID := t.pkgID(name, version)
//		if pkgID != "" && checksum != "" {
//			pkgs[pkgID] = digest.NewDigestFromString(digest.SHA256, checksum)
//		}
//	}
//	if err = scanner.Err(); err != nil {
//		return nil, xerrors.Errorf("scan error: %w", err)
//	}
//
//	return pkgs, nil
//}
//
//// parseDpkgStatus parses /var/lib/dpkg/status or /var/lib/dpkg/status/*
//func (t *Tracee) parseDpkgStatus(filePath string, r io.Reader, digests map[string]digest.Digest) ([]types.PackageInfo, error) {
//	var pkg *types.Package
//	pkgs := make(map[string]*types.Package)
//	pkgIDs := make(map[string]string)
//
//	scanner := NewScanner(r)
//	for scanner.Scan() {
//		header, err := scanner.Header()
//		if !errors.Is(err, io.EOF) && err != nil {
//			logger.Debugw("Parse error", "path", log.FilePath(filePath), "err", err)
//			continue
//		}
//
//		pkg = t.parseDpkgPkg(header)
//		if pkg != nil {
//			pkg.Digest = digests[pkg.ID]
//			pkgs[pkg.ID] = pkg
//			pkgIDs[pkg.Name] = pkg.ID
//		}
//	}
//
//	if err := scanner.Err(); err != nil {
//		return nil, xerrors.Errorf("scan error: %w", err)
//	}
//
//	t.consolidateDependencies(pkgs, pkgIDs)
//
//	return []types.PackageInfo{
//		{
//			FilePath: filePath,
//			Packages: lo.MapToSlice(pkgs, func(_ string, p *types.Package) types.Package {
//				return *p
//			}),
//		},
//	}, nil
//}
//
//func (t *Tracee) parseDpkgPkg(header textproto.MIMEHeader) *types.Package {
//	if isInstalled := t.parseStatus(header.Get("Status")); !isInstalled {
//		return nil
//	}
//
//	pkg := &types.Package{
//		Name:       header.Get("Package"),
//		Version:    header.Get("Version"),                 // Will be parsed later
//		DependsOn:  t.parseDepends(header.Get("Depends")), // Will be updated later
//		Maintainer: header.Get("Maintainer"),
//		Arch:       header.Get("Architecture"),
//	}
//	if pkg.Name == "" || pkg.Version == "" {
//		return nil
//	}
//
//	// Source line (Optional)
//	// Gives the name of the source package
//	// May also specifies a version
//	if src := header.Get("Source"); src != "" {
//		srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(src, -1)[0]
//		md := make(map[string]string)
//		for i, n := range srcCapture {
//			md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
//		}
//		pkg.SrcName = md["name"]
//		pkg.SrcVersion = md["version"]
//	}
//
//	// Source version and names are computed from binary package names and versions in dpkg.
//	// Source package name:
//	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
//	// Source package version:
//	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n355
//	if pkg.SrcName == "" {
//		pkg.SrcName = pkg.Name
//	}
//	if pkg.SrcVersion == "" {
//		pkg.SrcVersion = pkg.Version
//	}
//
//	if v, err := debVersion.NewVersion(pkg.Version); err != nil {
//		logger.Warnw("Invalid version debian", "package", pkg.Name, "version", pkg.Version)
//		return nil
//	} else {
//		pkg.ID = t.pkgID(pkg.Name, pkg.Version)
//		pkg.Version = v.Version()
//		pkg.Epoch = v.Epoch()
//		pkg.Release = v.Revision()
//	}
//
//	if v, err := debVersion.NewVersion(pkg.SrcVersion); err != nil {
//		logger.Warnw("Invalid source version debian", "package", pkg.Name, "version", pkg.SrcVersion)
//		return nil
//	} else {
//		pkg.SrcVersion = v.Version()
//		pkg.SrcEpoch = v.Epoch()
//		pkg.SrcRelease = v.Revision()
//	}
//
//	return pkg
//}
//
//func (t *Tracee) Required(filePath string, _ os.FileInfo) bool {
//	dir, fileName := filepath.Split(filePath)
//	if t.isListFile(dir, fileName) || filePath == statusFile || filePath == availableFile {
//		return true
//	}
//
//	// skip `*.md5sums` files from `status.d` directory
//	if dir == statusDir && filepath.Ext(fileName) != ".md5sums" {
//		return true
//	}
//	return false
//}
//
//func (t *Tracee) pkgID(name, version string) string {
//	return fmt.Sprintf("%s@%s", name, version)
//}
//
//func (t *Tracee) parseStatus(s string) bool {
//	for _, ss := range strings.Fields(s) {
//		if ss == "deinstall" || ss == "purge" {
//			return false
//		}
//	}
//	return true
//}
//
//func (t *Tracee) parseDepends(s string) []string {
//	// e.g. passwd, debconf (>= 0.5) | debconf-2.0
//	var dependencies []string
//	depends := strings.Split(s, ",")
//	for _, dep := range depends {
//		// e.g. gpgv | gpgv2 | gpgv1
//		for _, d := range strings.Split(dep, "|") {
//			d = t.trimVersionRequirement(d)
//
//			// Store only uniq package names here
//			d = strings.TrimSpace(d)
//			if !slices.Contains(dependencies, d) {
//				dependencies = append(dependencies, d)
//			}
//		}
//	}
//	return dependencies
//}
//
//func (t *Tracee) trimVersionRequirement(s string) string {
//	// e.g.
//	//	libapt-pkg6.0 (>= 2.2.4) => libapt-pkg6.0
//	//	adduser => adduser
//	s, _, _ = strings.Cut(s, "(")
//	return s
//}
//
//func (t *Tracee) consolidateDependencies(pkgs map[string]*types.Package, pkgIDs map[string]string) {
//	for _, pkg := range pkgs {
//		// e.g. libc6 => libc6@2.31-13+deb11u4
//		pkg.DependsOn = lo.FilterMap(pkg.DependsOn, func(d string, _ int) (string, bool) {
//			if pkgID, ok := pkgIDs[d]; ok {
//				return pkgID, true
//			}
//			return "", false
//		})
//		sort.Strings(pkg.DependsOn)
//		if len(pkg.DependsOn) == 0 {
//			pkg.DependsOn = nil
//		}
//	}
//}
//
//func (t *Tracee) isListFile(dir, fileName string) bool {
//	if dir != infoDir {
//		return false
//	}
//
//	return strings.HasSuffix(fileName, ".list")
//}
//
//func (t *Tracee) Type() analyzer.Type {
//	return analyzer.TypeDpkg
//}
//
//func (t *Tracee) Version() int {
//	return analyzerVersion
//}
//
//type dpkgScanner struct {
//	*bufio.Scanner
//}
//
//// NewScanner returns a new scanner that splits on empty lines.
//func NewScanner(r io.Reader) *dpkgScanner {
//	s := bufio.NewScanner(r)
//	// Package data may exceed default buffer size
//	// Increase the buffer default size by 2 times
//	buf := make([]byte, 0, 128*1024)
//	s.Buffer(buf, 128*1024)
//
//	s.Split(emptyLineSplit)
//	return &dpkgScanner{Scanner: s}
//}
//
//// Scan advances the scanner to the next token.
//func (s *dpkgScanner) Scan() bool {
//	return s.Scanner.Scan()
//}
//
//// Header returns the MIME header of the current scan.
//func (s *dpkgScanner) Header() (textproto.MIMEHeader, error) {
//	b := s.Bytes()
//	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
//	return reader.ReadMIMEHeader()
//}
//
//// emptyLineSplit is a bufio.SplitFunc that splits on empty lines.
//func emptyLineSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
//	if atEOF && len(data) == 0 {
//		return 0, nil, nil
//	}
//
//	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
//		// We have a full empty line terminated block.
//		return i + 2, data[0:i], nil
//	}
//
//	if atEOF {
//		// Return the rest of the data if we're at EOF.
//		return len(data), data, nil
//	}
//
//	return
//}
