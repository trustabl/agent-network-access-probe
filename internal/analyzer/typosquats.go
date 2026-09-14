package analyzer

// typosquatEntry records a documented PyPI supply-chain attack: a malicious or
// impersonating package name, the legitimate package it impersonates, and a
// short citation for the incident.
type typosquatEntry struct {
	LegitimatePackage string
	Note              string
}

// typosquatPackages is a static, offline deny-list of documented PyPI
// typosquats and malware-distributing packages (lowercase import name -> entry).
// This is a starter list, not an exhaustive feed — there is no live lookup by
// design, to keep static analysis fast and offline. Add new entries via PR as
// incidents are reported by PyPI, Sonatype, Checkpoint, ReversingLabs, Snyk,
// or Phylum.
// Keys are importable module names (valid Python identifiers — underscores,
// never hyphens), not PyPI distribution names, since that's what actually
// appears in an `import X` statement being scanned.
var typosquatPackages = map[string]typosquatEntry{
	"python3_dateutil": {LegitimatePackage: "python-dateutil", Note: "stole SSH/GPG keys; resided on PyPI ~1 year (Sysdig, 2022)"},
	"python_dateutils":  {LegitimatePackage: "python-dateutil", Note: "typosquat of python-dateutil, deployed cryptominer (Sonatype)"},
	"jeilyfish":          {LegitimatePackage: "jellyfish", Note: "letter-swap typosquat, stole SSH/GPG keys (Sysdig, 2022)"},
	"ulrlib3":            {LegitimatePackage: "urllib3", Note: "character-transposition typosquat of urllib3 (ReversingLabs)"},
	"urllib4":            {LegitimatePackage: "urllib3", Note: "version-number typosquat of urllib3 (ReversingLabs)"},
	"requestss":          {LegitimatePackage: "requests", Note: "double-letter typosquat of requests, deployed ransomware (Sonatype)"},
	"request5":           {LegitimatePackage: "requests", Note: "visual-substitution typosquat of requests (Sonatype)"},
	"coloraam":           {LegitimatePackage: "colorama", Note: "letter-transposition typosquat of colorama (Sonatype, 55-package campaign)"},
	"coloraama":          {LegitimatePackage: "colorama", Note: "letter-duplication typosquat of colorama (Sonatype)"},
	"colormaa":           {LegitimatePackage: "colorama", Note: "letter-transposition typosquat of colorama (Sonatype)"},
	"coolorama":          {LegitimatePackage: "colorama", Note: "letter-insertion typosquat of colorama (Sonatype)"},
	"cryptogarphy":       {LegitimatePackage: "cryptography", Note: "letter-transposition typosquat of cryptography (Sonatype)"},
	"pycrypto":           {LegitimatePackage: "pycryptodome", Note: "unmaintained since 2013 with known CVEs — risky, not just a name confusion"},
	"aio6":               {LegitimatePackage: "aiohttp", Note: "typosquat targeting aiohttp users (Bolster.ai PyPI supply-chain report)"},
	"aio5":               {LegitimatePackage: "aiohttp", Note: "typosquat targeting aiohttp users (Bolster.ai PyPI supply-chain report)"},
}
