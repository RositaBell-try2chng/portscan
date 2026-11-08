package portscan

import (
)

func Range(st, en uint16) ([]uint16, error) {
	//invalid ranges
	if st > en || st < 1 {
		return nil, ErrInvalidRange
	}
	ports := make([]uint16, 0, int(en)-int(st)+1)
	for i := int(st); i <= int(en); i++ {
		ports = append(ports, uint16(i))
	}
	return ports, nil
}

func FlexRange(args ...any) ([]uint16, error) {
	if len(args) == 0 {
		return nil, ErrNoPorts
	}
	portsMap := make(map[uint16]struct{})
	isValid := func(port uint16) bool {
		return port >= 1
	}

	for _, arg := range args {
		switch val := arg.(type) {
		case uint16:
			if isValid(val) {
				portsMap[val] = struct{}{}
			} else {
				return nil, ErrInvalidPort
			}
		case []uint16:
			if len(val) == 0 {
				return nil, ErrInvalidRange
			}
			for _, port := range val {
				if isValid(port) {
					portsMap[port] = struct{}{}
				} else {
					return nil, ErrInvalidPort
				}
			}
		case int:
			if val >= 1 && val <= 65535 {
				portsMap[uint16(val)] = struct{}{}
			} else {
				return nil, ErrInvalidPort
			}
		case []int:
			if len(val) == 0 {
				return nil, ErrInvalidRange
			}
			for _, port := range val {
				if port >= 1 && port <= 65535 {
					portsMap[uint16(port)] = struct{}{}
				} else {
					return nil, ErrInvalidPort
				}
			}
		default:
			return nil, ErrInvalidPort
		}
	}
	ports := make([]uint16, 0, len(portsMap))
	for port := range portsMap {
		ports = append(ports, port)
	}
	return ports, nil
}
