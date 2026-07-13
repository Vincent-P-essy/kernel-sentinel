package detection

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

var regularExpressions sync.Map

func Matches(event model.Event, block MatchBlock) bool {
	for _, condition := range block.All {
		if !matchCondition(event, condition) {
			return false
		}
	}
	if len(block.Any) == 0 {
		return true
	}
	for _, condition := range block.Any {
		if matchCondition(event, condition) {
			return true
		}
	}
	return false
}

func matchCondition(event model.Event, condition Condition) bool {
	actual, exists := event.Field(condition.Field)
	if condition.Op == "exists" {
		expected, ok := asBool(condition.Value)
		return ok && exists == expected
	}
	if !exists {
		return false
	}

	switch condition.Op {
	case "eq", "neq":
		matched := equalValues(actual, condition.Value)
		if condition.Op == "neq" {
			return !matched
		}
		return matched
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(condition.Value)))
	case "prefix":
		return strings.HasPrefix(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(condition.Value)))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(condition.Value)))
	case "regex":
		expression, ok := cachedRegularExpression(fmt.Sprint(condition.Value))
		return ok && expression.MatchString(fmt.Sprint(actual))
	case "in":
		for _, candidate := range toSlice(condition.Value) {
			if equalValues(actual, candidate) {
				return true
			}
		}
		return false
	case "gt", "gte", "lt", "lte":
		left, leftOK := asFloat(actual)
		right, rightOK := asFloat(condition.Value)
		if !leftOK || !rightOK {
			return false
		}
		switch condition.Op {
		case "gt":
			return left > right
		case "gte":
			return left >= right
		case "lt":
			return left < right
		default:
			return left <= right
		}
	default:
		return false
	}
}

func cachedRegularExpression(pattern string) (*regexp.Regexp, bool) {
	if cached, ok := regularExpressions.Load(pattern); ok {
		return cached.(*regexp.Regexp), true
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	actual, _ := regularExpressions.LoadOrStore(pattern, expression)
	return actual.(*regexp.Regexp), true
}

func equalValues(left interface{}, right interface{}) bool {
	if leftNumber, ok := asFloat(left); ok {
		if rightNumber, rightOK := asFloat(right); rightOK {
			return leftNumber == rightNumber
		}
	}
	if leftBool, ok := asBool(left); ok {
		if rightBool, rightOK := asBool(right); rightOK {
			return leftBool == rightBool
		}
	}
	return strings.EqualFold(fmt.Sprint(left), fmt.Sprint(right))
}

func asFloat(value interface{}) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case float64:
		return typed, true
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func asBool(value interface{}) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		return parsed, err == nil
	default:
		return false, false
	}
}

func toSlice(value interface{}) []interface{} {
	switch typed := value.(type) {
	case []interface{}:
		return typed
	case []string:
		values := make([]interface{}, len(typed))
		for index := range typed {
			values[index] = typed[index]
		}
		return values
	default:
		return []interface{}{value}
	}
}
