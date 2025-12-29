// webfingerprint-------------------------------------
// @file      : acmatch.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/29 22:25
// -------------------------------------------

package webfingerprint

import (
	"github.com/Autumn-27/ScopeSentry-Scan/internal/global"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
)

func AcRun(testTitle, testHeader, testBody string) []*types.Fingerprint {
	// 收集命中的指纹（按ID去重）
	matchedFingerprintsMap := make(map[string]*types.Fingerprint) // key: fingerprintID

	// 获取 matcher 引用，避免在函数执行过程中 global.WebFingers 被修改
	var matcher *types.ACMatcher
	if global.WebFingers == nil || global.WebFingers.ACMatcher == nil {
		return []*types.Fingerprint{}
	}
	matcher = global.WebFingers.ACMatcher

	// 匹配title并收集指纹
	if matcher.TitleMatcher != nil {
		titleMatches := matcher.TitleMatcher.Match([]byte(testTitle))
		for _, patternIndex := range titleMatches {
			if patternIndex < len(matcher.TitlePatterns) {
				p := matcher.TitlePatterns[patternIndex]
				if p.Fingerprint != nil {
					matchedFingerprintsMap[p.Fingerprint.ID] = p.Fingerprint
				}
			}
		}
	}

	// 匹配header并收集指纹
	if matcher.HeaderMatcher != nil {
		headerMatches := matcher.HeaderMatcher.Match([]byte(testHeader))
		for _, patternIndex := range headerMatches {
			if patternIndex < len(matcher.HeaderPatterns) {
				p := matcher.HeaderPatterns[patternIndex]
				if p.Fingerprint != nil {
					matchedFingerprintsMap[p.Fingerprint.ID] = p.Fingerprint
				}
			}
		}
	}

	// 匹配body并收集指纹
	if matcher.BodyMatcher != nil {
		bodyMatches := matcher.BodyMatcher.Match([]byte(testBody))
		for _, patternIndex := range bodyMatches {
			if patternIndex < len(matcher.BodyPatterns) {
				p := matcher.BodyPatterns[patternIndex]
				if p.Fingerprint != nil {
					matchedFingerprintsMap[p.Fingerprint.ID] = p.Fingerprint
				}
			}
		}
	}

	// 转换为切片并返回
	result := make([]*types.Fingerprint, 0, len(matchedFingerprintsMap))
	for _, fp := range matchedFingerprintsMap {
		result = append(result, fp)
	}
	return result
}
