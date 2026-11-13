package dnsfilter

// The catalog names the public blocklists the filter can use. Nothing here is copied from them: every list is
// downloaded at runtime from its own project, so it is always as current as the project publishes it, and each
// project's licence stays with the project. The licence text is shown to the user next to each source.

// Source is a blocklist project.
type Source struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Repo     string `json:"repo"`
	Formats  string `json:"formats"`
	License  string `json:"license"`
	Verified bool   `json:"verified"` // the download URLs below were fetched and checked
	Note     string `json:"note,omitempty"`
}

// List is one downloadable list.
type List struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Name     string `json:"name"`
	Category string `json:"category"`
	URL      string `json:"url"`
	Format   string `json:"format"`  // informational: the parser reads every format
	SizeMB   int    `json:"size_mb"` // download size, for the user's information
	Default  bool   `json:"default"` // used when its category is switched on
}

// Category is what the user chooses to block.
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Help  string `json:"help"`
}

var Categories = []Category{
	{"ads", "Advertising", "Ad servers, pop-ups and banner networks."},
	{"trackers", "Trackers and analytics", "Tracking, analytics and session-replay services."},
	{"malware", "Malware, phishing and scams", "Known malicious, phishing, scam, fraud and ransomware domains."},
	{"adult", "Adult content", "Pornography and other explicit sites."},
	{"gambling", "Gambling", "Online casinos, betting and gambling affiliates."},
	{"social", "Social media", "Social networks and their apps."},
	{"piracy", "Piracy and torrents", "Pirate streaming, file sharing and DDoS-for-hire sites."},
	{"fake", "Fake shops and misinformation", "Fake webshops, scam coupons and fake-news sites."},
	{"smarttv", "Smart TV telemetry", "Telemetry and ads from smart TVs and streaming sticks."},
	{"telemetry", "Phone and app telemetry", "Native vendor telemetry from Apple, Amazon, LG, TikTok and others. Can break some features."},
	{"crypto", "Cryptocurrency", "Crypto mining scripts and exchanges."},
	{"drugs", "Drugs", "Illegal drug marketplaces and vaping shops."},
}

// Sources lists the ten projects. Licences are as the project states them (or as reported when not verified).
var Sources = []Source{
	{"stevenblack", "StevenBlack/hosts", "https://github.com/StevenBlack/hosts", "hosts, with extensions", "MIT", true, ""},
	{"hagezi", "hagezi/dns-blocklists", "https://github.com/hagezi/dns-blocklists", "many formats, tiered", "GPL-3.0", true, "Downloaded through the project's jsDelivr CDN."},
	{"adguard", "AdguardTeam/AdGuardSDNSFilter", "https://github.com/AdguardTeam/AdGuardSDNSFilter", "adblock syntax, DNS-simplified", "GPL-3.0", true, ""},
	{"blocklistproject", "blocklistproject/Lists", "https://github.com/blocklistproject/Lists", "hosts, domain-only, dnsmasq, AdGuard", "Unlicense", true, ""},
	{"easylist", "easylist/easylist", "https://github.com/easylist/easylist", "adblock syntax (browser-oriented)", "not verified", true, "Browser-oriented: only the plain ||domain^ rules apply at DNS level; element and path rules are skipped."},
	{"mullvad", "mullvad/dns-blocklists", "https://github.com/mullvad/dns-blocklists", "Mullvad's composed lists", "not verified", false, "Reference only: Mullvad composes its lists from other projects in this catalog (Hagezi, Firebog and others, see their README) and publishes no composed file we could verify."},
	{"onehosts", "badmojr/1Hosts", "https://github.com/badmojr/1Hosts", "many client formats", "MPL-2.0", true, "The Lite and Xtra files were verified; the Pro path was not found."},
	{"perflyst", "Perflyst/PiHoleBlocklist", "https://github.com/Perflyst/PiHoleBlocklist", "domain lists plus a regex list", "MIT", true, "The regular-expression list is not used: the filter matches domains and their subdomains, not patterns."},
	{"oisd", "sjhgvr/oisd", "https://oisd.nl", "domainswild and ABP", "unconfirmed", true, ""},
	{"adaway", "AdAway/adaway.github.io", "https://github.com/AdAway/adaway.github.io", "hosts", "GPLv3+ (project)", true, ""},
}

const (
	hg = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/"
	sb = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
	bp = "https://blocklistproject.github.io/Lists/"
	pf = "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/"
)

// Lists is the catalog. Every URL was fetched and checked.
var Lists = []List{
	// Advertising
	{"stevenblack-unified", "stevenblack", "Unified hosts (ads and malware)", "ads", sb + "hosts", "hosts", 3, true},
	{"oisd-small", "oisd", "oisd small", "ads", "https://small.oisd.nl/domainswild2", "domainswild", 2, true},
	{"adguard-dns", "adguard", "AdGuard DNS filter", "ads", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adblock", 5, true},
	{"oisd-big", "oisd", "oisd big", "ads", "https://big.oisd.nl/domainswild2", "domainswild", 5, false},
	{"hagezi-light", "hagezi", "Hagezi Light", "ads", hg + "light.txt", "wildcard", 3, false},
	{"hagezi-pro", "hagezi", "Hagezi Pro", "ads", hg + "pro.txt", "wildcard", 5, false},
	{"hagezi-popupads", "hagezi", "Hagezi pop-up ads", "ads", hg + "popupads.txt", "wildcard", 2, false},
	{"easylist", "easylist", "EasyList", "ads", "https://easylist.to/easylist/easylist.txt", "adblock", 2, false},
	{"onehosts-lite", "onehosts", "1Hosts Lite", "ads", "https://badmojr.github.io/1Hosts/Lite/domains.txt", "domains", 5, false},
	{"onehosts-xtra", "onehosts", "1Hosts Xtra", "ads", "https://badmojr.github.io/1Hosts/Xtra/hosts.txt", "hosts", 31, false},
	{"adaway", "adaway", "AdAway", "ads", "https://adaway.org/hosts.txt", "hosts", 1, false},
	{"blocklistproject-ads", "blocklistproject", "Block List Project: ads", "ads", bp + "ads.txt", "hosts", 7, false},
	// Trackers
	{"easyprivacy", "easylist", "EasyPrivacy", "trackers", "https://easylist.to/easylist/easyprivacy.txt", "adblock", 2, true},
	{"blocklistproject-tracking", "blocklistproject", "Block List Project: tracking", "trackers", bp + "tracking.txt", "hosts", 1, true},
	{"perflyst-android", "perflyst", "Android tracking", "trackers", pf + "android-tracking.txt", "domains", 1, true},
	{"perflyst-sessionreplay", "perflyst", "Session replay", "trackers", pf + "SessionReplay.txt", "domains", 1, true},
	// Malware
	{"blocklistproject-malware", "blocklistproject", "Block List Project: malware", "malware", bp + "malware.txt", "hosts", 1, true},
	{"blocklistproject-phishing", "blocklistproject", "Block List Project: phishing", "malware", bp + "phishing.txt", "hosts", 1, true},
	{"blocklistproject-scam", "blocklistproject", "Block List Project: scams", "malware", bp + "scam.txt", "hosts", 1, true},
	{"blocklistproject-fraud", "blocklistproject", "Block List Project: fraud", "malware", bp + "fraud.txt", "hosts", 1, true},
	{"blocklistproject-ransomware", "blocklistproject", "Block List Project: ransomware", "malware", bp + "ransomware.txt", "hosts", 1, true},
	{"blocklistproject-abuse", "blocklistproject", "Block List Project: abuse", "malware", bp + "abuse.txt", "hosts", 1, false},
	{"hagezi-tif", "hagezi", "Hagezi Threat Intelligence Feeds", "malware", hg + "tif.txt", "wildcard", 29, false},
	// Adult
	{"stevenblack-porn", "stevenblack", "StevenBlack with the porn extension", "adult", sb + "alternates/porn/hosts", "hosts", 5, true},
	{"hagezi-nsfw", "hagezi", "Hagezi NSFW", "adult", hg + "nsfw.txt", "wildcard", 2, true},
	{"oisd-nsfw", "oisd", "oisd nsfw", "adult", "https://nsfw.oisd.nl/domainswild2", "domainswild", 9, false},
	{"blocklistproject-porn", "blocklistproject", "Block List Project: porn", "adult", bp + "porn.txt", "hosts", 26, false},
	// Gambling
	{"stevenblack-gambling", "stevenblack", "StevenBlack with the gambling extension", "gambling", sb + "alternates/gambling/hosts", "hosts", 3, true},
	{"blocklistproject-gambling", "blocklistproject", "Block List Project: gambling", "gambling", bp + "gambling.txt", "hosts", 1, true},
	{"hagezi-gambling", "hagezi", "Hagezi gambling", "gambling", hg + "gambling.txt", "wildcard", 13, false},
	// Social
	{"stevenblack-social", "stevenblack", "StevenBlack with the social extension", "social", sb + "alternates/social/hosts", "hosts", 3, true},
	{"blocklistproject-facebook", "blocklistproject", "Block List Project: Facebook", "social", bp + "facebook.txt", "hosts", 1, false},
	{"blocklistproject-twitter", "blocklistproject", "Block List Project: Twitter", "social", bp + "twitter.txt", "hosts", 1, false},
	{"blocklistproject-tiktok", "blocklistproject", "Block List Project: TikTok", "social", bp + "tiktok.txt", "hosts", 1, false},
	// Piracy
	{"hagezi-antipiracy", "hagezi", "Hagezi anti-piracy", "piracy", hg + "anti.piracy.txt", "wildcard", 2, true},
	{"blocklistproject-piracy", "blocklistproject", "Block List Project: piracy", "piracy", bp + "piracy.txt", "hosts", 1, true},
	{"blocklistproject-torrent", "blocklistproject", "Block List Project: torrents", "piracy", bp + "torrent.txt", "hosts", 1, false},
	// Fake
	{"hagezi-fake", "hagezi", "Hagezi fake shops and scams", "fake", hg + "fake.txt", "wildcard", 1, true},
	{"stevenblack-fakenews", "stevenblack", "StevenBlack with the fake news extension", "fake", sb + "alternates/fakenews/hosts", "hosts", 3, true},
	// Smart TV
	{"perflyst-smarttv", "perflyst", "Smart TV blocklist", "smarttv", pf + "SmartTV.txt", "domains", 1, true},
	{"perflyst-firetv", "perflyst", "Amazon Fire TV", "smarttv", pf + "AmazonFireTV.txt", "domains", 1, true},
	{"blocklistproject-smarttv", "blocklistproject", "Block List Project: smart TV", "smarttv", bp + "smart-tv.txt", "hosts", 1, false},
	{"hagezi-lgwebos", "hagezi", "Hagezi LG webOS telemetry", "smarttv", hg + "native.lgwebos.txt", "wildcard", 1, true},
	// Telemetry
	{"hagezi-apple", "hagezi", "Hagezi Apple telemetry", "telemetry", hg + "native.apple.txt", "wildcard", 1, true},
	{"hagezi-amazon", "hagezi", "Hagezi Amazon telemetry", "telemetry", hg + "native.amazon.txt", "wildcard", 1, true},
	{"hagezi-tiktok", "hagezi", "Hagezi TikTok telemetry", "telemetry", hg + "native.tiktok.txt", "wildcard", 1, true},
	// Crypto and drugs
	{"blocklistproject-crypto", "blocklistproject", "Block List Project: crypto", "crypto", bp + "crypto.txt", "hosts", 1, true},
	{"blocklistproject-drugs", "blocklistproject", "Block List Project: drugs", "drugs", bp + "drugs.txt", "hosts", 1, true},
	{"blocklistproject-vaping", "blocklistproject", "Block List Project: vaping", "drugs", bp + "vaping.txt", "hosts", 1, false},
}

func listByID(id string) (List, bool) {
	for _, l := range Lists {
		if l.ID == id {
			return l, true
		}
	}
	return List{}, false
}

func categoryKnown(id string) bool {
	for _, c := range Categories {
		if c.ID == id {
			return true
		}
	}
	return false
}
