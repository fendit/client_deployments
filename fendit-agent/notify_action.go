package main

// securityActionText returns a user-facing title and body for each action type.
// These are the only strings displayed to the end user — keep them clear and
// non-technical. No PIDs, IPs, filenames, or internal component names.
func securityActionText(action string) (title, body string) {
	switch action {
	case "kill_process":
		return "Threat Blocked",
			"Fendit Security terminated a suspicious process to protect your device."
	case "suspend_process":
		return "Threat Contained",
			"Fendit Security paused a suspicious process for investigation."
	case "block_ip":
		return "Connection Blocked",
			"Fendit Security blocked a suspicious network connection."
	case "quarantine":
		return "File Quarantined",
			"Fendit Security isolated a suspicious file to protect your device."
	case "isolate":
		return "Device Isolated",
			"Fendit Security has isolated this device from the network. Contact your IT administrator."
	default:
		return "", ""
	}
}
