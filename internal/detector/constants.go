// Package detector provides security detection capabilities
// Constants ported from agent_hunter_v2/backend/app/apve/constants.py
package detector

// LOLBins - Living Off The Land Binaries (182 total)
// Categorized by attack technique

// LOLBinsExecute - Code execution binaries (31)
var LOLBinsExecute = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "mshta.exe": true,
	"wscript.exe": true, "cscript.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"msiexec.exe": true, "installutil.exe": true, "regasm.exe": true, "regsvcs.exe": true,
	"msbuild.exe": true, "cmstp.exe": true, "control.exe": true, "explorer.exe": true,
	"forfiles.exe": true, "pcalua.exe": true, "scriptrunner.exe": true, "syncappvpublishingserver.exe": true,
	"hh.exe": true, "infdefaultinstall.exe": true, "msconfig.exe": true, "msdeploy.exe": true,
	"presentationhost.exe": true, "ieexec.exe": true, "bash.exe": true, "wsl.exe": true,
	"winrm.cmd": true, "winrs.exe": true, "at.exe": true,
}

// LOLBinsDownload - Download capability binaries (16)
var LOLBinsDownload = map[string]bool{
	"certutil.exe": true, "bitsadmin.exe": true, "curl.exe": true, "wget.exe": true,
	"powershell.exe": true, "expand.exe": true, "extrac32.exe": true, "findstr.exe": true,
	"hh.exe": true, "ieexec.exe": true, "makecab.exe": true, "replace.exe": true,
	"finger.exe": true, "desktopimgdownldr.exe": true, "esentutl.exe": true, "print.exe": true,
}

// LOLBinsBypass - Security bypass binaries (27)
var LOLBinsBypass = map[string]bool{
	"regsvr32.exe": true, "rundll32.exe": true, "msbuild.exe": true, "mshta.exe": true,
	"cmstp.exe": true, "installutil.exe": true, "regasm.exe": true, "regsvcs.exe": true,
	"odbcconf.exe": true, "msiexec.exe": true, "control.exe": true, "csc.exe": true,
	"jsc.exe": true, "vbc.exe": true, "appsyncpublishingserver.exe": true, "dnscmd.exe": true,
	"ftp.exe": true, "mavinject.exe": true, "microsoft.workflow.compiler.exe": true,
	"msdeploy.exe": true, "msdt.exe": true, "msiexec.exe": true, "pcwrun.exe": true,
	"presentationhost.exe": true, "syncappvpublishingserver.exe": true, "te.exe": true,
	"tracker.exe": true,
}

// LOLBinsRecon - Reconnaissance binaries (35)
var LOLBinsRecon = map[string]bool{
	"whoami.exe": true, "hostname.exe": true, "ipconfig.exe": true, "net.exe": true,
	"net1.exe": true, "netstat.exe": true, "arp.exe": true, "route.exe": true,
	"nslookup.exe": true, "systeminfo.exe": true, "tasklist.exe": true, "qprocess.exe": true,
	"query.exe": true, "sc.exe": true, "wmic.exe": true, "fsutil.exe": true,
	"reg.exe": true, "cmdkey.exe": true, "nltest.exe": true, "dsquery.exe": true,
	"gpresult.exe": true, "getmac.exe": true, "netsh.exe": true, "pathping.exe": true,
	"ping.exe": true, "tracert.exe": true, "tree.exe": true, "where.exe": true,
	"qwinsta.exe": true, "rwinsta.exe": true, "auditpol.exe": true, "findstr.exe": true,
	"nbtstat.exe": true, "ver.exe": true, "w32tm.exe": true,
}

// LOLBinsPersist - Persistence binaries (12)
var LOLBinsPersist = map[string]bool{
	"schtasks.exe": true, "at.exe": true, "sc.exe": true, "reg.exe": true,
	"wmic.exe": true, "netsh.exe": true, "bcdboot.exe": true, "bcdedit.exe": true,
	"bootcfg.exe": true, "eventvwr.exe": true, "mmc.exe": true, "taskkill.exe": true,
}

// LOLBinsCreds - Credential access binaries (8)
var LOLBinsCreds = map[string]bool{
	"cmdkey.exe": true, "vaultcmd.exe": true, "ntdsutil.exe": true, "procdump.exe": true,
	"comsvcs.dll": true, "rundll32.exe": true, "reg.exe": true, "esentutl.exe": true,
}

// LOLBinsLateral - Lateral movement binaries (9)
var LOLBinsLateral = map[string]bool{
	"wmic.exe": true, "psexec.exe": true, "winrm.cmd": true, "winrs.exe": true,
	"mstsc.exe": true, "ssh.exe": true, "runas.exe": true, "net.exe": true,
	"schtasks.exe": true,
}

// LOLBinsCompile - Compilation binaries (12)
var LOLBinsCompile = map[string]bool{
	"csc.exe": true, "vbc.exe": true, "jsc.exe": true, "msbuild.exe": true,
	"ilasm.exe": true, "aspnet_compiler.exe": true, "microsoft.workflow.compiler.exe": true,
	"cl.exe": true, "link.exe": true, "ml.exe": true, "ml64.exe": true, "ildasm.exe": true,
}

// LOLBinsMisc - Miscellaneous suspicious binaries (32)
var LOLBinsMisc = map[string]bool{
	"vssadmin.exe": true, "wbadmin.exe": true, "cipher.exe": true, "takeown.exe": true,
	"icacls.exe": true, "cacls.exe": true, "attrib.exe": true, "compact.exe": true,
	"copy.exe": true, "del.exe": true, "erase.exe": true, "move.exe": true,
	"ren.exe": true, "replace.exe": true, "robocopy.exe": true, "xcopy.exe": true,
	"format.exe": true, "diskpart.exe": true, "defrag.exe": true, "sfc.exe": true,
	"dism.exe": true, "bcdedit.exe": true, "bootrec.exe": true, "reagentc.exe": true,
	"shutdown.exe": true, "logoff.exe": true, "tscon.exe": true, "tsdiscon.exe": true,
	"msg.exe": true, "quser.exe": true, "change.exe": true, "shadow.exe": true,
}

// AllLOLBins combines all LOLBin categories
var AllLOLBins = mergeMaps(
	LOLBinsExecute, LOLBinsDownload, LOLBinsBypass, LOLBinsRecon,
	LOLBinsPersist, LOLBinsCreds, LOLBinsLateral, LOLBinsCompile, LOLBinsMisc,
)

// SuspiciousChains - Parent-Child process chains (102 total)
var SuspiciousChains = map[string][]string{
	// Web Shell chains (21)
	"w3wp.exe":       {"cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "net.exe", "whoami.exe"},
	"httpd.exe":      {"cmd.exe", "powershell.exe", "sh.exe", "bash.exe"},
	"nginx.exe":      {"cmd.exe", "powershell.exe"},
	"tomcat.exe":     {"cmd.exe", "powershell.exe"},
	"java.exe":       {"cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe"},
	"javaw.exe":      {"cmd.exe", "powershell.exe"},
	"php.exe":        {"cmd.exe", "powershell.exe"},
	"php-cgi.exe":    {"cmd.exe", "powershell.exe"},
	"node.exe":       {"cmd.exe", "powershell.exe"},
	"python.exe":     {"cmd.exe", "powershell.exe"},
	"ruby.exe":       {"cmd.exe", "powershell.exe"},

	// Office Macro chains (22)
	"winword.exe":    {"cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"},
	"excel.exe":      {"cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe"},
	"powerpnt.exe":   {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe"},
	"outlook.exe":    {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"},
	"msaccess.exe":   {"cmd.exe", "powershell.exe", "cscript.exe"},
	"mspub.exe":      {"cmd.exe", "powershell.exe"},
	"onenote.exe":    {"cmd.exe", "powershell.exe"},
	"visio.exe":      {"cmd.exe", "powershell.exe"},

	// Browser chains (12)
	"chrome.exe":     {"cmd.exe", "powershell.exe"},
	"firefox.exe":    {"cmd.exe", "powershell.exe"},
	"iexplore.exe":   {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe"},
	"msedge.exe":     {"cmd.exe", "powershell.exe"},
	"brave.exe":      {"cmd.exe", "powershell.exe"},
	"opera.exe":      {"cmd.exe", "powershell.exe"},

	// PDF Reader chains (7)
	"acrord32.exe":   {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"},
	"acrobat.exe":    {"cmd.exe", "powershell.exe"},
	"foxitreader.exe": {"cmd.exe", "powershell.exe"},

	// Service chains (13)
	"services.exe":   {"cmd.exe", "powershell.exe"},
	"svchost.exe":    {"cmd.exe", "powershell.exe", "whoami.exe", "net.exe"},
	"lsass.exe":      {"cmd.exe", "powershell.exe"},
	"spoolsv.exe":    {"cmd.exe", "powershell.exe"},
	"searchindexer.exe": {"cmd.exe", "powershell.exe"},

	// Script chains (10)
	"wscript.exe":    {"cmd.exe", "powershell.exe", "mshta.exe", "cscript.exe"},
	"cscript.exe":    {"cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe"},
	"mshta.exe":      {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "rundll32.exe"},

	// WMI chains (8)
	"wmiprvse.exe":   {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe"},
	"wmic.exe":       {"cmd.exe", "powershell.exe"},
	"scrcons.exe":    {"cmd.exe", "powershell.exe"},

	// DCOM chains (5)
	"dllhost.exe":    {"cmd.exe", "powershell.exe", "cscript.exe"},
	"mmc.exe":        {"cmd.exe", "powershell.exe"},

	// Task Scheduler chains (4)
	"taskeng.exe":    {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"},
	"taskhostw.exe":  {"cmd.exe", "powershell.exe"},
}

// SuspiciousPorts - Common malicious/suspicious ports (46)
var SuspiciousPorts = map[uint16]string{
	// Reverse shells
	4444:  "Metasploit default",
	5555:  "Common reverse shell",
	6666:  "Common reverse shell",
	1337:  "Elite/Leet",
	31337: "Elite/Back Orifice",
	12345: "NetBus",
	27374: "SubSeven",
	1234:  "Common backdoor",

	// C2 HTTP(S)
	8080:  "HTTP Proxy/C2",
	8443:  "HTTPS Alt/C2",
	4443:  "HTTPS Alt/C2",
	9000:  "PHP-FPM/C2",
	9001:  "Tor/C2",
	9002:  "C2",
	9090:  "Web Alt/C2",
	8888:  "Web Alt/C2",

	// IRC
	6667:  "IRC",
	6697:  "IRC SSL",
	7000:  "IRC Alt",

	// Remote management
	5985:  "WinRM HTTP",
	5986:  "WinRM HTTPS",
	22:    "SSH",
	23:    "Telnet",

	// Database
	1433:  "MSSQL",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",

	// RDP
	3389:  "RDP",
	33890: "RDP Alt",

	// SMB/NetBIOS
	445:   "SMB",
	139:   "NetBIOS",
	137:   "NetBIOS-NS",
	138:   "NetBIOS-DGM",

	// Other suspicious
	53:    "DNS (unusual for endpoint)",
	69:    "TFTP",
	161:   "SNMP",
	389:   "LDAP",
	636:   "LDAPS",
	1080:  "SOCKS",
	3128:  "Squid Proxy",
	8000:  "HTTP Alt",
	8081:  "HTTP Alt",
	8082:  "HTTP Alt",
}

// PathAnomalyPatterns - Suspicious path patterns (10)
var PathAnomalyPatterns = []string{
	`^\\\\[^\\]+\\`,                           // UNC path (remote execution)
	`:[^\\/:*?"<>|{}]+\.(exe|dll)$`,           // ADS (Alternate Data Stream)
	`\.(doc|pdf|xls|ppt)\.(exe|dll|scr|bat|cmd|ps1)$`, // Double extension
	`\\[0-9]{6,}\.(exe|dll)$`,                 // Numeric filename
	`(?i)\\windows\\system\\(?!32)`,           // Fake system path
	`(?i)\\temp\\.*\.(exe|dll|ps1|bat|cmd)$`,  // Temp folder executable
	`(?i)\\appdata\\.*\.(exe|dll)$`,           // AppData executable
	`(?i)\\users\\public\\.*\.(exe|dll)$`,     // Public folder executable
	`(?i)\\programdata\\.*\.(exe|dll)$`,       // ProgramData executable
	`(?i)\\recycler\\`,                        // Recycle bin execution
}

// TyposquatTargets - System processes commonly typosquatted (24)
var TyposquatTargets = map[string]string{
	"svchost.exe":    `C:\Windows\System32\svchost.exe`,
	"lsass.exe":      `C:\Windows\System32\lsass.exe`,
	"csrss.exe":      `C:\Windows\System32\csrss.exe`,
	"services.exe":   `C:\Windows\System32\services.exe`,
	"smss.exe":       `C:\Windows\System32\smss.exe`,
	"wininit.exe":    `C:\Windows\System32\wininit.exe`,
	"winlogon.exe":   `C:\Windows\System32\winlogon.exe`,
	"explorer.exe":   `C:\Windows\explorer.exe`,
	"spoolsv.exe":    `C:\Windows\System32\spoolsv.exe`,
	"taskhost.exe":   `C:\Windows\System32\taskhost.exe`,
	"taskhostw.exe":  `C:\Windows\System32\taskhostw.exe`,
	"dwm.exe":        `C:\Windows\System32\dwm.exe`,
	"conhost.exe":    `C:\Windows\System32\conhost.exe`,
	"dllhost.exe":    `C:\Windows\System32\dllhost.exe`,
	"rundll32.exe":   `C:\Windows\System32\rundll32.exe`,
	"msiexec.exe":    `C:\Windows\System32\msiexec.exe`,
	"audiodg.exe":    `C:\Windows\System32\audiodg.exe`,
	"searchindexer.exe": `C:\Windows\System32\SearchIndexer.exe`,
	"wuauclt.exe":    `C:\Windows\System32\wuauclt.exe`,
	"sppsvc.exe":     `C:\Windows\System32\sppsvc.exe`,
	"ctfmon.exe":     `C:\Windows\System32\ctfmon.exe`,
	"wmiprvse.exe":   `C:\Windows\System32\wbem\WmiPrvSE.exe`,
	"System":         `System`,
	"Idle":           `System Idle Process`,
}

// Helper function to merge maps
func mergeMaps(maps ...map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// LOLBinCategory returns the category of a LOLBin
func LOLBinCategory(name string) string {
	if LOLBinsExecute[name] {
		return "Execute"
	}
	if LOLBinsDownload[name] {
		return "Download"
	}
	if LOLBinsBypass[name] {
		return "Bypass"
	}
	if LOLBinsRecon[name] {
		return "Recon"
	}
	if LOLBinsPersist[name] {
		return "Persist"
	}
	if LOLBinsCreds[name] {
		return "Credential Access"
	}
	if LOLBinsLateral[name] {
		return "Lateral Movement"
	}
	if LOLBinsCompile[name] {
		return "Compile"
	}
	if LOLBinsMisc[name] {
		return "Misc"
	}
	return "Unknown"
}
