package is

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrBadType  = errors.New("bad value type")
	ErrBadRange = errors.New("bad value range")

	timeType = reflect.TypeOf(time.Time{})
	nilType  = reflect.TypeOf([]byte(nil))
)

// convert value to float64, return error on failed
func toFloat(in any) (f64 float64, err error) {
	switch tVal := in.(type) {
	case nil:
		f64 = 0
	case string:
		f64, err = strconv.ParseFloat(strings.TrimSpace(tVal), 64)
	case int:
		f64 = float64(tVal)
	case int8:
		f64 = float64(tVal)
	case int16:
		f64 = float64(tVal)
	case int32:
		f64 = float64(tVal)
	case int64:
		f64 = float64(tVal)
	case uint:
		f64 = float64(tVal)
	case uint8:
		f64 = float64(tVal)
	case uint16:
		f64 = float64(tVal)
	case uint32:
		f64 = float64(tVal)
	case uint64:
		f64 = float64(tVal)
	case float32:
		f64 = float64(tVal)
	case float64:
		f64 = tVal
	case time.Duration:
		f64 = float64(tVal)
	case json.Number:
		f64, err = tVal.Float64()
	default:
		err = ErrBadType
	}
	return
}

// convert string to int64, return error on failed
func toInt64(in any) (i64 int64, err error) {
	switch tVal := in.(type) {
	case nil:
		i64 = 0
	case string:
		i64, err = strconv.ParseInt(strings.TrimSpace(tVal), 10, 0)
	case int:
		i64 = int64(tVal)
	case int8:
		i64 = int64(tVal)
	case int16:
		i64 = int64(tVal)
	case int32:
		i64 = int64(tVal)
	case int64:
		i64 = tVal
	case uint:
		i64 = int64(tVal)
	case uint8:
		i64 = int64(tVal)
	case uint16:
		i64 = int64(tVal)
	case uint32:
		i64 = int64(tVal)
	case uint64:
		i64 = int64(tVal)
	case float32:
		i64 = int64(tVal)
	case float64:
		i64 = int64(tVal)
	case time.Duration:
		i64 = int64(tVal)
	case json.Number:
		i64, err = tVal.Int64()
	default:
		err = ErrBadType
	}
	return
}

// compString compare string, returns the first op second
func compString(first, second, op string) bool {
	rs := strings.Compare(first, second)
	if rs < 0 {
		return op == "<" || op == "<="
	} else if rs > 0 {
		return op == ">" || op == ">="
	} else {
		return op == ">=" || op == "<=" || op == "="
	}
}

func compTime(first, dstTime time.Time, op string) (ok bool) {
	switch op {
	case "<":
		return first.Before(dstTime)
	case "<=":
		return first.Before(dstTime) || first.Equal(dstTime)
	case ">":
		return first.After(dstTime)
	case ">=":
		return first.After(dstTime) || first.Equal(dstTime)
	case "=":
		return first.Equal(dstTime)
	case "!=":
		return !first.Equal(dstTime)
	}
	return
}

func compNum[T int64 | float64 | uint64](first, second T, op string) bool {
	switch op {
	case "<":
		return first < second
	case "<=":
		return first <= second
	case ">":
		return first > second
	case ">=":
		return first >= second
	case "=":
		return first == second
	case "!=":
		return first != second
	}
	return false
}

func compBool(first, second bool, op string) bool {
	return compNum(boolToInt(first), boolToInt(second), op)
}

func boolToInt(a bool) int64 {
	if a {
		return 1
	} else {
		return 0
	}
}

// get reflect value length
func calcLength(val any) int {
	v := reflect.Indirect(reflect.ValueOf(val))

	// (u)int use width.
	switch v.Kind() {
	case reflect.String:
		return len([]rune(v.String()))
	case reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return v.Len()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return len(strconv.FormatInt(int64(v.Uint()), 10))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return len(strconv.FormatInt(v.Int(), 10))
	case reflect.Float32, reflect.Float64:
		return len(fmt.Sprint(v.Interface()))
	}

	// cannot get length
	return -1
}

func getLength(a any, rune bool) (int, error) {
	field := reflect.ValueOf(a)

	//if !field.IsValid() || field.IsNil() {
	//	return 0, nil
	//}

	switch field.Kind() {
	case reflect.String:
		if rune {
			return utf8.RuneCountInString(field.String()), nil
		}
		return field.Len(), nil

	case reflect.Slice, reflect.Map, reflect.Array:
		return field.Len(), nil

	case reflect.Ptr:
		if field.Type().Elem().Kind() == reflect.Array {
			// 类型声明中的长度
			return field.Type().Elem().Len(), nil
		}
	}

	return 0, ErrBadType
}
