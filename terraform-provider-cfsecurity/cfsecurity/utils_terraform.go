package cfsecurity

import (
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"hash/crc32"
	"net/http"
	"reflect"
)

// getListOfStructs
func getListOfStructs(v interface{}) []map[string]interface{} {
	if vvSet, ok := v.(*schema.Set); ok {
		v = vvSet.List()
	}
	vvv := []map[string]interface{}{}
	for _, vv := range v.([]interface{}) {
		vvv = append(vvv, vv.(map[string]interface{}))
	}
	return vvv
}

// getListChanges -
func getListMapChanges(old interface{}, new interface{}, match func(source, item map[string]interface{}) bool) (remove []map[string]interface{}, add []map[string]interface{}) {
	if vvSet, ok := old.(*schema.Set); ok {
		old = vvSet.List()
	}
	if vvSet, ok := new.(*schema.Set); ok {
		new = vvSet.List()
	}
	oldL := old.([]interface{})
	newL := new.([]interface{})

	for _, source := range oldL {
		toDelete := true
		for _, item := range newL {
			if match(source.(map[string]interface{}), item.(map[string]interface{})) {
				toDelete = false
				break
			}
		}
		if toDelete {
			remove = append(remove, source.(map[string]interface{}))
		}
	}
	for _, source := range newL {
		toAdd := true
		for _, item := range oldL {
			if match(source.(map[string]interface{}), item.(map[string]interface{})) {
				toAdd = false
				break
			}
		}
		if toAdd {
			add = append(add, source.(map[string]interface{}))
		}
	}

	return remove, add
}

// return the intersection of 2 slices ([1, 1, 3, 4, 5, 6] & [2, 3, 6] >> [3, 6])
// sources and items must be array of whatever and element type can be whatever and can be different
// match function must return true if item and source given match
func intersectSlices(sources interface{}, items interface{}, match func(source, item interface{}) bool) []interface{} {
	sourceValue := reflect.ValueOf(sources)
	itemsValue := reflect.ValueOf(items)
	final := make([]interface{}, 0)
	for i := 0; i < sourceValue.Len(); i++ {
		inside := false
		src := sourceValue.Index(i).Interface()
		for p := 0; p < itemsValue.Len(); p++ {
			item := itemsValue.Index(p).Interface()
			if match(src, item) {
				inside = true
				break
			}
		}
		if inside {
			final = append(final, src)
		}
	}
	return final
}

// Try to find in a list of whatever an element
func isInSlice(objects interface{}, match func(object interface{}) bool) bool {
	objectsValue := reflect.ValueOf(objects)
	for i := 0; i < objectsValue.Len(); i++ {
		object := objectsValue.Index(i).Interface()
		if match(object) {
			return true
		}
	}
	return false
}

func isNotFoundErr(err error) bool {
	if httpErr, ok := err.(cfclient.CloudFoundryHTTPError); ok {
		return httpErr.StatusCode == http.StatusNotFound
	}
	return false
}

func StringHashCode(s string) int {
	v := int(crc32.ChecksumIEEE([]byte(s)))
	if v >= 0 {
		return v
	}
	if -v >= 0 {
		return -v
	}
	// v == MinInt
	return 0
}
