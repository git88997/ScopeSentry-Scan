// configupdater-------------------------------------
// @file      : webfinger.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/29 20:58
// -------------------------------------------

package configupdater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"

	"github.com/cloudflare/ahocorasick"
	"gopkg.in/yaml.v3"
)

// NewACMatcher 创建新的AC自动机匹配器
func NewACMatcher() *types.ACMatcher {
	return &types.ACMatcher{
		TitlePatterns:     make([]types.PatternInfo, 0),
		HeaderPatterns:    make([]types.PatternInfo, 0),
		BodyPatterns:      make([]types.PatternInfo, 0),
		NonACFingerprints: make([]*types.Fingerprint, 0),
	}
}

// LoadFingerprintsFromDir 从目录加载所有指纹文件
func LoadFingerprintsFromDir(dirPath string) ([]*types.Fingerprint, error) {
	var fingerprints []*types.Fingerprint

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".yaml") {
			fp, err := LoadFingerprintWithID(path)
			if err != nil {
				// 忽略加载失败的文件，继续处理其他文件
				return nil
			}
			fingerprints = append(fingerprints, fp)
		}

		return nil
	})

	return fingerprints, err
}

// LoadFingerprintWithID 加载带ID的指纹文件
func LoadFingerprintWithID(filepath string) (*types.Fingerprint, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	var fingerprint types.Fingerprint
	if err := yaml.Unmarshal(data, &fingerprint); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &fingerprint, nil
}

// extractPatternsFromRule 从rule中提取patterns
// 返回提取到的pattern信息列表，如果无法提取则返回空列表
// 对于OR逻辑的条件组，会收集组内所有符合条件的pattern
// 对于AND逻辑的rule，如果包含OR组，保留OR组内的所有patterns；否则选择最佳的pattern
func extractPatternsFromRule(rule types.Rule, fingerprint *types.Fingerprint, ruleIndex int) []types.PatternInfo {
	// 从rule的conditions中提取patterns
	patterns := extractPatternsFromConditionGroup(rule.Conditions, rule.Logic, fingerprint, ruleIndex)

	if len(patterns) == 0 {
		return nil
	}

	return patterns
}

func isConditionGroup(condition types.Condition) bool {
	return condition.Logic != "" && condition.Location == ""
}

// extractPatternsFromConditionGroup 从条件组中提取patterns（递归处理无限嵌套）
// logic: 当前条件组的逻辑（AND或OR）
func extractPatternsFromConditionGroup(conditions []types.Condition, logic string, fingerprint *types.Fingerprint, ruleIndex int) []types.PatternInfo {
	var allPatterns []types.PatternInfo

	// 遍历所有条件
	for _, condition := range conditions {
		// 如果是嵌套条件组
		if isConditionGroup(condition) {
			// 递归提取嵌套组中的patterns
			nestedPatterns := extractPatternsFromConditionGroup(condition.Conditions, condition.Logic, fingerprint, ruleIndex)
			allPatterns = append(allPatterns, nestedPatterns...)
			continue
		}

		// 处理普通条件：只处理contains类型，且location为title/header/body
		if condition.MatchType == "contains" &&
			(condition.Location == "title" || condition.Location == "header" || condition.Location == "body") &&
			condition.Pattern != "" {
			allPatterns = append(allPatterns, types.PatternInfo{
				Pattern:     condition.Pattern,
				Location:    condition.Location,
				Fingerprint: fingerprint,
				RuleIndex:   ruleIndex,
			})
		}
	}

	if len(allPatterns) == 0 {
		return nil
	}

	// 根据逻辑类型处理patterns
	if logic == "OR" {
		// OR逻辑：返回所有patterns（因为OR组内的所有patterns都需要匹配）
		// 去重：相同的pattern只保留一个（基于pattern字符串和location）
		return deduplicatePatterns(allPatterns)
	} else {
		// AND逻辑：需要检查是否包含来自OR组的patterns
		// 如果所有patterns都来自同一个OR组（通过递归收集），保留所有
		// 否则只选择一个最佳的pattern

		// 检查是否有OR组（通过检查是否有多个相同优先级的patterns）
		// 更简单的方法：如果patterns来自不同的条件组层级，可能需要选择最佳
		// 但实际上，如果AND组内包含OR组，OR组的所有patterns都应该保留
		// 如果AND组内只有AND子组或普通条件，只选择一个最佳的

		// 简化处理：对于AND逻辑，如果patterns数量大于1，检查是否来自OR组
		// 由于我们无法直接判断patterns的来源，采用保守策略：
		// 如果AND组内直接或间接包含OR组，应该保留所有patterns
		// 否则只选择一个最佳的

		// 检查conditions中是否包含OR组（递归检查）
		hasORGroup := hasORGroupInConditions(conditions)

		if hasORGroup {
			// 如果包含OR组，保留所有patterns（因为OR组内的所有patterns都需要匹配）
			return allPatterns
		} else {
			// 否则只选择一个最佳的pattern
			best := selectBestPattern(allPatterns)
			if best != nil {
				return []types.PatternInfo{*best}
			}
			return nil
		}
	}
}

// hasORGroupInConditions 递归检查conditions中是否包含OR逻辑的条件组
func hasORGroupInConditions(conditions []types.Condition) bool {
	for _, condition := range conditions {
		if isConditionGroup(condition) {
			if condition.Logic == "OR" {
				return true
			}
			// 递归检查嵌套组
			if hasORGroupInConditions(condition.Conditions) {
				return true
			}
		}
	}
	return false
}

// deduplicatePatterns 去重patterns（基于pattern字符串和location）
func deduplicatePatterns(patterns []types.PatternInfo) []types.PatternInfo {
	if len(patterns) <= 1 {
		return patterns
	}

	seen := make(map[string]bool)
	result := make([]types.PatternInfo, 0, len(patterns))

	for _, p := range patterns {
		key := p.Location + ":" + p.Pattern
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result
}

// selectBestPattern 根据优先级和长度选择最佳pattern（用于AND逻辑）
// 优先级：title > header > body
// 对于相同优先级，选择最长的
func selectBestPattern(candidates []types.PatternInfo) *types.PatternInfo {
	if len(candidates) == 0 {
		return nil
	}

	// 定义优先级
	priority := map[string]int{
		"title":  3,
		"header": 2,
		"body":   1,
	}

	var best *types.PatternInfo
	bestPriority := 0
	bestLength := 0

	for i := range candidates {
		candidate := &candidates[i]
		p := priority[candidate.Location]
		length := len(candidate.Pattern)

		// 优先级更高，或者优先级相同但长度更长
		if p > bestPriority || (p == bestPriority && length > bestLength) {
			best = candidate
			bestPriority = p
			bestLength = length
		}
	}

	return best
}

// BuildACMatcher 构建AC自动机匹配器
func BuildACMatcher(fingerprints []*types.Fingerprint) *types.ACMatcher {
	matcher := NewACMatcher()

	// 分别收集title、header、body的pattern
	titlePatterns := make([]string, 0)
	headerPatterns := make([]string, 0)
	bodyPatterns := make([]string, 0)

	// 遍历所有fingerprint
	for _, fingerprint := range fingerprints {
		// 先检查所有rules是否都能提取到pattern
		allRulesHavePattern := true
		allRulePatterns := make([][]types.PatternInfo, 0, len(fingerprint.Rules))

		// 遍历每个rule，尝试提取patterns
		for ruleIndex, rule := range fingerprint.Rules {
			patterns := extractPatternsFromRule(rule, fingerprint, ruleIndex)
			if len(patterns) == 0 {
				// 如果任何一个rule无法提取pattern，标记为false
				allRulesHavePattern = false
				// 不立即break，继续检查其他rules以便调试
				// break
			} else {
				allRulePatterns = append(allRulePatterns, patterns)
			}
		}

		// 如果所有rules都能提取到pattern，才添加到AC自动机
		if !allRulesHavePattern {
			// 如果有任何一个rule无法提取pattern，整个fingerprint放入非AC列表
			matcher.NonACFingerprints = append(matcher.NonACFingerprints, fingerprint)
			continue
		}

		// 如果所有rules都能提取到pattern，才添加到AC自动机
		if allRulesHavePattern && len(allRulePatterns) > 0 {
			// 将所有rule的patterns添加到对应的AC自动机
			for _, rulePatterns := range allRulePatterns {
				for _, PatternInfo := range rulePatterns {
					switch PatternInfo.Location {
					case "title":
						matcher.TitlePatterns = append(matcher.TitlePatterns, PatternInfo)
						titlePatterns = append(titlePatterns, PatternInfo.Pattern)
					case "header":
						matcher.HeaderPatterns = append(matcher.HeaderPatterns, PatternInfo)
						headerPatterns = append(headerPatterns, PatternInfo.Pattern)
					case "body":
						matcher.BodyPatterns = append(matcher.BodyPatterns, PatternInfo)
						bodyPatterns = append(bodyPatterns, PatternInfo.Pattern)
					}
				}
			}
		} else {
			// 如果有任何一个rule无法提取pattern，整个fingerprint放入非AC列表
			matcher.NonACFingerprints = append(matcher.NonACFingerprints, fingerprint)
		}
	}

	// 构建AC自动机
	if len(titlePatterns) > 0 {
		matcher.TitleMatcher = ahocorasick.NewStringMatcher(titlePatterns)
	}
	if len(headerPatterns) > 0 {
		matcher.HeaderMatcher = ahocorasick.NewStringMatcher(headerPatterns)
	}
	if len(bodyPatterns) > 0 {
		matcher.BodyMatcher = ahocorasick.NewStringMatcher(bodyPatterns)
	}

	return matcher
}

//
//func main() {
//	//test_main()
//	// 从fingers文件夹加载所有指纹文件
//	fmt.Println("开始加载指纹文件...")
//	fingerprints, err := LoadFingerprintsFromDir("fingers")
//	if err != nil {
//		log.Fatalf("加载指纹文件失败: %v", err)
//	}
//	fmt.Printf("✓ 成功加载 %d 个指纹文件\n", len(fingerprints))
//
//	// 构建AC自动机
//	fmt.Println("\n开始构建AC自动机...")
//	matcher := BuildACMatcher(fingerprints)
//	//
//	//// 统计信息
//	//totalFingerprints := len(fingerprints)
//	//acFingerprints := totalFingerprints - len(matcher.NonACFingerprints)
//	//nonACFingerprints := len(matcher.NonACFingerprints)
//	//
//	//// 输出统计结果
//	//fmt.Println("\n" + strings.Repeat("=", 60))
//	//fmt.Println("AC自动机构建完成 - 统计结果")
//	//fmt.Println(strings.Repeat("=", 60))
//	//fmt.Printf("总指纹数量:        %d\n", totalFingerprints)
//	//fmt.Printf("可以使用AC的指纹:   %d (%.2f%%)\n", acFingerprints, float64(acFingerprints)/float64(totalFingerprints)*100)
//	//fmt.Printf("无法使用AC的指纹:   %d (%.2f%%)\n", nonACFingerprints, float64(nonACFingerprints)/float64(totalFingerprints)*100)
//	//fmt.Println(strings.Repeat("=", 60))
//	//
//	//// Pattern统计
//	//fmt.Printf("\nPattern统计:\n")
//	//fmt.Printf("  Title patterns:  %d\n", len(matcher.TitlePatterns))
//	//fmt.Printf("  Header patterns: %d\n", len(matcher.HeaderPatterns))
//	//fmt.Printf("  Body patterns:   %d\n", len(matcher.BodyPatterns))
//	//fmt.Printf("  总patterns:      %d\n", len(matcher.TitlePatterns)+len(matcher.HeaderPatterns)+len(matcher.BodyPatterns))
//
//	// 如果需要，可以输出无法使用AC的指纹列表
//	//if nonACFingerprints > 0 && nonACFingerprints <= 20 {
//	//	fmt.Printf("\n无法使用AC的指纹列表 (前%d个):\n", nonACFingerprints)
//	//	for i, fp := range matcher.NonACFingerprints {
//	//		if i >= 20 {
//	//			break
//	//		}
//	//		fmt.Printf("  [%d] %s (ID: %s)\n", i+1, fp.Name, fp.ID)
//	//	}
//	//} else if nonACFingerprints > 20 {
//	//	fmt.Printf("\n无法使用AC的指纹列表 (前20个):\n")
//	//	for i := 0; i < 20 && i < len(matcher.NonACFingerprints); i++ {
//	//		fp := matcher.NonACFingerprints[i]
//	//		fmt.Printf("  [%d] %s (ID: %s)\n", i+1, fp.Name, fp.ID)
//	//	}
//	//	fmt.Printf("  ... 还有 %d 个指纹无法使用AC\n", nonACFingerprints-20)
//	//}
//
//	// 匹配测试
//	fmt.Println("\n" + strings.Repeat("=", 60))
//	fmt.Println("AC自动机匹配测试")
//	fmt.Println(strings.Repeat("=", 60))
//
//	// 测试数据（可以修改这些值进行测试）
//	testTitle := "D-Link DSL-2640B 下一代防火墙安全网关"
//	testHeader := "Server: mini_httpd\nContent-Type: text/html Server: AvigilonGateway"
//	testBody := "Product : DSL-2640B"
//
//	fmt.Printf("测试数据:\n")
//	fmt.Printf("  Title:  %q\n", testTitle)
//	fmt.Printf("  Header: %q\n", testHeader)
//	fmt.Printf("  Body:   %q\n", testBody)
//
//	// 收集命中的指纹（按ID去重）
//	type MatchedFingerprint struct {
//		FingerprintID   string
//		FingerprintName string
//		MatchedRules    []int // 匹配到的rule索引列表
//	}
//
//	matchedFingerprintsMap := make(map[string]*MatchedFingerprint) // key: fingerprintID
//
//	// 匹配title并收集指纹
//	if matcher.TitleMatcher != nil {
//		titleMatches := matcher.TitleMatcher.Match([]byte(testTitle))
//		for _, patternIndex := range titleMatches {
//			if patternIndex < len(matcher.TitlePatterns) {
//				p := matcher.TitlePatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// 检查ruleIndex是否已存在
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// 匹配header并收集指纹
//	if matcher.HeaderMatcher != nil {
//		headerMatches := matcher.HeaderMatcher.Match([]byte(testHeader))
//		for _, patternIndex := range headerMatches {
//			if patternIndex < len(matcher.HeaderPatterns) {
//				p := matcher.HeaderPatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// 检查ruleIndex是否已存在
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// 匹配body并收集指纹
//	if matcher.BodyMatcher != nil {
//		bodyMatches := matcher.BodyMatcher.Match([]byte(testBody))
//		for _, patternIndex := range bodyMatches {
//			if patternIndex < len(matcher.BodyPatterns) {
//				p := matcher.BodyPatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// 检查ruleIndex是否已存在
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// 输出匹配结果
//	fmt.Printf("\n匹配结果:\n")
//	fmt.Printf("  命中的指纹数量: %d (按ID去重后)\n", len(matchedFingerprintsMap))
//
//	if len(matchedFingerprintsMap) > 0 {
//		fmt.Println("\n命中的指纹ID列表:")
//		// 只输出去重后的ID
//		for _, fp := range matchedFingerprintsMap {
//			fmt.Printf("  %s\n", fp.FingerprintID)
//		}
//	} else {
//		fmt.Println("  未匹配到任何指纹")
//	}
//}
