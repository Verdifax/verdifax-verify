package main

// Round 62, N29: a genuine AMD SEV-SNP report proves which firmware the
// guest booted (its launch measurement) and how it was launched (its guest
// policy). The verifier states both on every hardware record. A launch
// measurement covers the guest firmware the machine started from, not the
// Verdifax server program that runs on it, so it is named as firmware.

// pinnedFirmware lists the launch measurements of the guest firmware
// Verdifax's hardware machines boot, each with the machines it was read
// from. A measurement not listed is stated as one Verdifax does not pin;
// --strict-hardware fails it.
var pinnedFirmware = map[string]string{
	// Read from every published hardware report: the October 2026 hardware
	// evidence run (key 2) and attested.verdifax.com's runs of November 14,
	// 2026 (key 4), both AWS EC2 SEV-SNP guests in us-east-2.
	"7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766": "the AWS EC2 SEV-SNP guest firmware of Verdifax's hardware machines (the October 2026 hardware evidence run and attested.verdifax.com)",
}

// strictHardware is --strict-hardware: a hardware record whose report has
// debug on, or whose firmware Verdifax does not pin, fails.
var strictHardware bool

// hardwareStatement states the report's debug setting and firmware, and
// whether --strict-hardware fails them.
func hardwareStatement(debug bool, measurementHex string) (statement string, strictFailure string) {
	debugWords := "debug off"
	if debug {
		debugWords = "debug ON, the host could read this machine's memory"
	}
	firmwareWords := "firmware not one Verdifax pins"
	machine, pinned := pinnedFirmware[measurementHex]
	if pinned {
		firmwareWords = "firmware matches " + machine
	}
	statement = debugWords + "; " + firmwareWords
	var why []string
	if debug {
		why = append(why, "the report has debug on")
	}
	if !pinned {
		why = append(why, "its firmware is not one Verdifax pins")
	}
	if len(why) > 0 {
		strictFailure = "--strict-hardware: " + joinAnd(why)
	}
	return statement, strictFailure
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1 : len(parts)-1] {
		out += ", " + p
	}
	return out + " and " + parts[len(parts)-1]
}
