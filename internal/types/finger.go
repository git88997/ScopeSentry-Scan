// types-------------------------------------
// @file      : finger.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/28 23:11
// -------------------------------------------

package types

import "github.com/cloudflare/ahocorasick"

// Fingerprint 指纹定义
type Fingerprint struct {
	Name           string `yaml:"name"`
	ID             string `yaml:"id"`
	Tags           string `yaml:"tags"` // 关联 POC
	Category       string `yaml:"category"`
	ParentCategory string `yaml:"parent_category"`
	Company        string `yaml:"company"`
	Rules          []Rule `yaml:"rules"`
}

// Rule 规则定义
type Rule struct {
	Logic      string      `yaml:"logic"` // AND 或 OR
	Conditions []Condition `yaml:"conditions"`
}

// Condition 条件定义（支持普通条件和嵌套条件组）
type Condition struct {
	// 普通条件字段
	Location    string `yaml:"location,omitempty"`   // body, header, title, request
	MatchType   string `yaml:"match_type,omitempty"` // regex, contains, extract, active
	Pattern     string `yaml:"pattern,omitempty"`
	Group       int    `yaml:"group,omitempty"`
	SaveAs      string `yaml:"save_as,omitempty"`
	Path        string `yaml:"path,omitempty"`
	DynamicPath string `yaml:"dynamic_path,omitempty"`
	Method      string `yaml:"method,omitempty"`

	// 嵌套条件组字段
	Logic      string      `yaml:"logic,omitempty"`      // AND 或 OR（用于嵌套组）
	Conditions []Condition `yaml:"conditions,omitempty"` // 子条件或嵌套组
}

type PatternInfo struct {
	Pattern     string       // pattern字符串
	Location    string       // title, header, body
	Fingerprint *Fingerprint // 关联的fingerprint
	RuleIndex   int          // 关联的rule索引
}

type WebFingerCore struct {
	ACMatcher *ACMatcher
}

type ACMatcher struct {
	TitleMatcher   *ahocorasick.Matcher
	HeaderMatcher  *ahocorasick.Matcher
	BodyMatcher    *ahocorasick.Matcher
	TitlePatterns  []PatternInfo
	HeaderPatterns []PatternInfo
	BodyPatterns   []PatternInfo
	// 无法使用AC自动机的fingerprint列表
	NonACFingerprints []*Fingerprint
}
