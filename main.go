package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cryptera-device-security/pkcs11mod"
	"github.com/miekg/pkcs11"
)

type KeyServerBackend struct {
	/*
	   initialized bool
	   objects     []pkcsObject
	   findIdx    int
	*/
}

var _initialized bool
var _objects []pkcsObject
var _token string
var _client http.Client
var _cfg Config
var _sessionMu sync.Mutex
var _nextSessionHandle pkcs11.SessionHandle = 1
var _sessions = map[pkcs11.SessionHandle]*sessionState{}

type sessionState struct {
	findIdx      int
	findObjects  []int
	signKey      string
	signFormat   string
	inputPadding string
	rw           bool
	loggedIn     bool
}

func boolToFlag(enabled bool, flag uint) uint {
	if enabled {
		return flag
	}
	return 0
}

func (b KeyServerBackend) Initialize() error {
	if _initialized {
		return pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	}

	_cfg = LoadConfig()

	timeoutStr := os.Getenv("KSC_HTTP_CLIENT_TIMEOUT")
	timeout := time.Second * 10 // Default timeout in seconds
	if timeoutStr != "" {
		if parsedTimeout, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = parsedTimeout
			fmt.Printf("Using timeout from environment variable: %s\n", timeout)
		} else {
			fmt.Println("Invalid HTTP_CLIENT_TIMEOUT value, using default timeout")
		}
	} else {
		fmt.Println("No timeout set in environment variable, using default timeout")
	}

	client := http.Client{
		Timeout: timeout,
	}
	_client = client

	// Look for token in environment variable
	envToken := os.Getenv("KSC_ID_TOKEN")
	if envToken != "" {
		_token = envToken
		fmt.Println("Using token from environment variable")
	} else {
		// Fallback to getting token using getToken function
		token, err := getToken(_client, _cfg["username"], _cfg["password"])
		if err != nil {
			fmt.Println("Error: getToken failed")
			return pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
		}
		_token = token
		fmt.Println("Using token from getToken function")
	}

	certs, err := getCerts(_client, _token)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error: getCerts failed")
		return pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	}

	_objects = parseCerts(certs)

	_initialized = true
	return nil
}

func (b KeyServerBackend) Finalize() error {
	if !_initialized {
		return pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	_sessionMu.Lock()
	_sessions = map[pkcs11.SessionHandle]*sessionState{}
	_nextSessionHandle = 1
	_sessionMu.Unlock()
	_initialized = false
	return nil
}

func (b KeyServerBackend) GetInfo() (pkcs11.Info, error) {
	if !_initialized {
		return pkcs11.Info{}, pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	info := pkcs11.Info{
		CryptokiVersion:    pkcs11.Version{Major: 2, Minor: 20},
		ManufacturerID:     "Cryptera A/S",
		Flags:              0,
		LibraryDescription: "Cryptera KeyServer PKCS11 module",
		LibraryVersion:     pkcs11.Version{Major: 0, Minor: 1},
	}

	return info, nil
}

func (b KeyServerBackend) GetSlotList(tokenPresent bool) ([]uint, error) {
	if !_initialized {
		return nil, pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	slots := []uint{0}

	return slots, nil
}

func (b KeyServerBackend) GetSlotInfo(slotId uint) (pkcs11.SlotInfo, error) {
	if slotId != 0 {
		return pkcs11.SlotInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	info := pkcs11.SlotInfo{
		SlotDescription: "Cryptera KeyServer slot",
		ManufacturerID:  "Cryptera A/S",
		Flags:           pkcs11.CKF_TOKEN_PRESENT | pkcs11.CKF_TOKEN_INITIALIZED | pkcs11.CKF_HW_SLOT,
		HardwareVersion: pkcs11.Version{Major: 0, Minor: 1},
		FirmwareVersion: pkcs11.Version{Major: 0, Minor: 1},
	}

	return info, nil
}

func (b KeyServerBackend) GetTokenInfo(slotId uint) (pkcs11.TokenInfo, error) {
	if slotId != 0 {
		return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	info := pkcs11.TokenInfo{
		Label:           "KEYSERVER",
		ManufacturerID:  "Cryptera",
		Model:           "KeyServer",
		Flags:           pkcs11.CKF_TOKEN_INITIALIZED | pkcs11.CKF_TOKEN_PRESENT,
		HardwareVersion: pkcs11.Version{Major: 0, Minor: 1},
		FirmwareVersion: pkcs11.Version{Major: 0, Minor: 1},
	}

	return info, nil
}

func (b KeyServerBackend) GetMechanismList(slotId uint) ([]*pkcs11.Mechanism, error) {
	if slotId != 0 {
		return nil, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	m := make([]*pkcs11.Mechanism, 2)
	m[0] = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	m[1] = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)

	return m, nil
}

func (b KeyServerBackend) GetMechanismInfo(slotId uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	if slotId != 0 {
		return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	if len(m) != 1 {
		return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}
	switch m[0].Mechanism {
	case pkcs11.CKM_RSA_PKCS:
		return pkcs11.MechanismInfo{
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      pkcs11.CKF_SIGN,
		}, nil
	case pkcs11.CKM_ECDSA:
		return pkcs11.MechanismInfo{
			MinKeySize: 521,
			MaxKeySize: 521,
			Flags:      pkcs11.CKF_SIGN,
		}, nil
	default:
		return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}
}

func (b KeyServerBackend) InitPIN(pkcs11.SessionHandle, string) error {
	fmt.Println(">>> InitPin")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SetPIN(pkcs11.SessionHandle, string, string) error {
	fmt.Println(">>> SetPin")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) OpenSession(_ uint, flags uint) (pkcs11.SessionHandle, error) {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	handle := _nextSessionHandle
	_nextSessionHandle++
	_sessions[handle] = &sessionState{
		rw: (flags & pkcs11.CKF_RW_SESSION) != 0,
	}

	return handle, nil
}

func (b KeyServerBackend) CloseSession(handle pkcs11.SessionHandle) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	if _, ok := _sessions[handle]; !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	delete(_sessions, handle)
	return nil
}

func (b KeyServerBackend) CloseAllSessions(uint) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	_sessions = map[pkcs11.SessionHandle]*sessionState{}
	return nil
}

func (b KeyServerBackend) GetSessionInfo(handle pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[handle]
	if !ok {
		return pkcs11.SessionInfo{}, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	sessionStateValue := uint(pkcs11.CKS_RO_PUBLIC_SESSION)
	if state.rw {
		sessionStateValue = pkcs11.CKS_RW_PUBLIC_SESSION
	}
	if state.loggedIn {
		if state.rw {
			sessionStateValue = pkcs11.CKS_RW_USER_FUNCTIONS
		} else {
			sessionStateValue = pkcs11.CKS_RO_USER_FUNCTIONS
		}
	}

	return pkcs11.SessionInfo{
		SlotID:      0,
		State:       sessionStateValue,
		Flags:       pkcs11.CKF_SERIAL_SESSION | boolToFlag(state.rw, pkcs11.CKF_RW_SESSION),
		DeviceError: 0,
	}, nil
}

func (b KeyServerBackend) GetOperationState(pkcs11.SessionHandle) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SetOperationState(pkcs11.SessionHandle, []byte, pkcs11.ObjectHandle, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) Login(handle pkcs11.SessionHandle, _ uint, _ string) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[handle]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	state.loggedIn = true
	return nil
}

func (b KeyServerBackend) Logout(handle pkcs11.SessionHandle) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[handle]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	state.loggedIn = false
	return nil
}

func (b KeyServerBackend) CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	fmt.Println(">>> CreateObject")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) CopyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	fmt.Println(">>> CopyObject")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
	fmt.Println(">>> DestroyObject")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (b KeyServerBackend) GetObjectSize(pkcs11.SessionHandle, pkcs11.ObjectHandle) (uint, error) {
	fmt.Println(">>> GetObjectSize")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) GetAttributeValue(sessHandle pkcs11.SessionHandle, objHandle pkcs11.ObjectHandle, temp []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	objId := int(objHandle) - 1
	if objId >= len(_objects) {
		return nil, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	results := make([]*pkcs11.Attribute, len(temp))
	missingAttr := false

	for i, t := range temp {
		results[i] = &pkcs11.Attribute{
			Type:  t.Type,
			Value: nil,
		}

		for _, attr := range _objects[objId] {
			if attr.Type == t.Type {
				results[i] = attr
				break
			}
		}

		if results[i].Value == nil {
			missingAttr = true
		}
	}

	if missingAttr {
		return results, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
	}

	return results, nil
}

func (b KeyServerBackend) SetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func findAttr(obj []*pkcs11.Attribute, ta *pkcs11.Attribute) *pkcs11.Attribute {
	for _, attr := range obj {
		if attr.Type == ta.Type {
			return attr
		}
	}
	return nil
}

func objectMatch(obj, temp []*pkcs11.Attribute) bool {
	if temp == nil {
		return true
	}
	for _, ta := range temp {
		attr := findAttr(obj, ta)
		if attr == nil {
			return false
		}
		if !reflect.DeepEqual(ta.Value, attr.Value) {
			return false
		}
	}
	return true

}

func (b KeyServerBackend) FindObjectsInit(session pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[session]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	state.findIdx = 0
	state.findObjects = make([]int, 0, len(_objects))

	for i, o := range _objects {
		if objectMatch(o, temp) {
			state.findObjects = append(state.findObjects, i)
		}
	}
	return nil
}

func (b KeyServerBackend) FindObjects(session pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[session]
	if !ok {
		return nil, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	if state.findIdx >= len(state.findObjects) {
		return nil, false, nil
	}

	handle := pkcs11.ObjectHandle(state.findObjects[state.findIdx] + 1)
	state.findIdx++

	return []pkcs11.ObjectHandle{handle}, false, nil
}

func (b KeyServerBackend) FindObjectsFinal(session pkcs11.SessionHandle) error {
	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[session]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	state.findIdx = 0
	state.findObjects = nil
	return nil
}

func (b KeyServerBackend) EncryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) Encrypt(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) EncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) EncryptFinal(pkcs11.SessionHandle) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DecryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DecryptFinal(pkcs11.SessionHandle) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DigestInit(pkcs11.SessionHandle, []*pkcs11.Mechanism) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) Digest(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DigestUpdate(pkcs11.SessionHandle, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DigestKey(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DigestFinal(pkcs11.SessionHandle) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func getAttribute(obj pkcsObject, attrType uint) ([]byte, bool) {
	for _, a := range obj {
		if a.Type == attrType {
			return a.Value, true
		}
	}
	return nil, false
}

func (b KeyServerBackend) SignInit(sessHandle pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, objHandle pkcs11.ObjectHandle) error {
	if len(mechanisms) != 1 {
		return pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}
	mech := *mechanisms[0]

	if mech.Mechanism != pkcs11.CKM_ECDSA && mech.Mechanism != pkcs11.CKM_RSA_PKCS {
		return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	}

	_sessionMu.Lock()
	defer _sessionMu.Unlock()

	state, ok := _sessions[sessHandle]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	key := int(objHandle) - 1
	label, ok := getAttribute(_objects[key], pkcs11.CKA_LABEL)
	if !ok {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	ktype, ok := getAttribute(_objects[key], pkcs11.CKA_KEY_TYPE)
	if !ok {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	kt := binary.LittleEndian.Uint64(ktype)
	if kt == pkcs11.CKK_RSA {
		state.signFormat = "asn1"
		state.inputPadding = "digestinfo"
	} else {
		state.signFormat = "p1363"
		state.inputPadding = "none"
	}

	state.signKey = string(label)

	return nil
}

func (b KeyServerBackend) Sign(sessHandle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	_sessionMu.Lock()
	state, ok := _sessions[sessHandle]
	_sessionMu.Unlock()
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	op := _cfg["op-id"]
	desc := _cfg["op-desc"]
	if len(desc) < 8 {
		desc += strings.Repeat("-", 8-len(desc))
	}
	hash := hex.EncodeToString(data)

	sign, err := getSign(_client, _token, op, desc, state.signKey, hash, state.inputPadding, state.signFormat)
	if err != nil {
		fmt.Println("getSign error, desc:" + desc + " odid:" + op)
		return nil, err
	}

	return sign, nil
}

func (b KeyServerBackend) SignUpdate(pkcs11.SessionHandle, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SignFinal(pkcs11.SessionHandle) ([]byte, error) {
	//return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
	return nil, nil
}

func (b KeyServerBackend) SignRecoverInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SignRecover(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) VerifyInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) Verify(pkcs11.SessionHandle, []byte, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) VerifyUpdate(pkcs11.SessionHandle, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) VerifyFinal(pkcs11.SessionHandle, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) VerifyRecoverInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) VerifyRecover(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DigestEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DecryptDigestUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SignEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DecryptVerifyUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) GenerateKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) GenerateKeyPair(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	return 0, 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) SeedRandom(pkcs11.SessionHandle, []byte) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) GenerateRandom(pkcs11.SessionHandle, int) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b KeyServerBackend) WaitForSlotEvent(uint) chan pkcs11.SlotEvent {
	/*
		sl := make(chan pkcs11.SlotEvent, 1) // hold one element
	*/
	//return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
	return nil
}

func init() {
	backend := KeyServerBackend{}
	pkcs11mod.SetBackend(backend)
}

func main() {
}
