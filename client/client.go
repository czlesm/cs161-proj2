package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type fourkeys struct {
    PubKey userlib.PKEEncKey
    PrivKey userlib.PKEDecKey
    SignKey userlib.DSSignKey
    VerifyKey userlib.DSVerifyKey
    privkey_marshalled []byte
}

type threekeys struct {
    SymmKey []byte
    SignKey userlib.DSSignKey
    VerifyKey userlib.DSVerifyKey
}

type User struct {
	Username string
    FK fourkeys    
}

func getUUID(str string) (uuid.UUID, error) {
	d, err := uuid.FromBytes(userlib.Hash([]byte(str))[:16])
	return d, err
}

// str1, str2, ...
func hashUUIDs(strs ...string) (uuid.UUID, error) {
	var s string
    for _, str := range strs {
		s += str
	}
    d, err := uuid.FromBytes(userlib.Hash([]byte(s))[:16])
	return d, err
}

func hashUUID(strs ...interface{}) (uuid.UUID, error) {
	var s []byte
    for _, str := range strs {
		switch str := str.(type) {
		case string:
			s = append(s, str...)
		case []byte:
			s = append(s, str...)
		default:
			panic("unexpected type")
		}
	}
	d, err := uuid.FromBytes(userlib.Hash([]byte(s))[:16])
	return d, err
    
}


// NOTE: The following methods have toy (insecure!) implementations.

func genFK() (*fourkeys, error) {
    pk, sk, err := userlib.PKEKeyGen()
    if err != nil {
        return nil, err
    }
    nk, vk, err := userlib.DSKeyGen()
    if err != nil {
        return nil, err
    }
    pmarshalled, err := json.Marshal(sk)
    return &fourkeys{pk, sk, nk, vk, pmarshalled}, nil
}

func genTK() (*threekeys, error) {
    tk := userlib.RandomBytes(userlib.AESBlockSizeBytes)
    nk, vk, err := userlib.DSKeyGen()
    if err != nil {
        return nil, err
    }
    return &threekeys{tk, nk, vk}, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	if _, ok := userlib.KeystoreGet(username + ".pubkey"); ok {
		return nil, errors.New("username already exists")
	}
    filename, err := hashUUID("userfile.", username, ".", password)
	if err != nil {
		return nil, err
	}
	var fk *fourkeys
	fk, err = genFK()
	if err != nil {
		return nil, err
	}
    userdata.FK = *fk
    content, err := json.Marshal(userdata)
    if err != nil {
		return nil, err
	}
    userlib.DatastoreSet(filename, content)
    var publicName = username + ".pubkey"
	userlib.KeystoreSet(publicName, userdata.FK.PubKey)
	var veryifyName = username + ".verifykey"
	userlib.KeystoreSet(veryifyName, userdata.FK.VerifyKey)
    return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
    filename, err := hashUUID("userfile.", username, ".", password)
	if err != nil {
		return nil, err
	}
	
    if content, ok := userlib.DatastoreGet(filename); ok {
		err = json.Unmarshal(content, &userdata)
		if err != nil {
			return nil, err
		}
        userdata.FK.privkey_marshalled, err = json.Marshal(userdata.FK.PrivKey)
        if err != nil {
			return nil, err
		}
		return &userdata, nil
	} else {
		return nil, errors.New(strings.ToTitle("user not found"))
	}
}

type Chunk struct {
    // iv []byte
    Content []byte
    Signature []byte
}

func makeChunk(content []byte, tk* threekeys) (*Chunk, error) {
	var chunk Chunk
    iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
    chunk.Content = userlib.SymEnc(tk.SymmKey, iv, content)
	var err error
    chunk.Signature, err = userlib.DSSign(tk.SignKey, chunk.Content)
    if err != nil {
        return nil, err
    }
    return &chunk, nil
}

func verifyChunk(chunk Chunk, tk threekeys) error {
    return userlib.DSVerify(tk.VerifyKey, chunk.Content, chunk.Signature)
}

type fileB struct {
    FilenameC uuid.UUID
    TK threekeys
    Typ int
}

const TYPE_FINAL = 0
const TYPE_RELAY = 1

func (userdata *User) createOrGetFile(filename string) (FB *fileB, err error) {
    filenameB, err := hashUUID(userdata.FK.privkey_marshalled, "-file-", filename)
	if err != nil {
		return nil, err
	}
    contentB, ok := userlib.DatastoreGet(filenameB)
    if !ok {
        fileTK, err := genTK()
		if err != nil {
			return nil, err
		}
        filenameC := uuid.New()
		
        filecontentB := fileB{filenameC, *fileTK, TYPE_FINAL}
		
		
        contentB, err := json.Marshal(filecontentB)
        if err != nil {
            return nil, err
        }
		userlib.DatastoreSet(filenameB, contentB)
        return &filecontentB, nil
    }
    filecontentB := fileB{}
	
    err = json.Unmarshal(contentB, &filecontentB)
	if err != nil {
		return nil, err
	}
	for {
        if filecontentB.Typ == TYPE_FINAL {
            break
        } else if filecontentB.Typ == TYPE_RELAY {
	        filenameC := filecontentB.FilenameC
            contentC, ok := userlib.DatastoreGet(filenameC)
            if !ok {
				return nil, errors.New(strings.ToTitle("file not found"))
			}
            err = json.Unmarshal(contentC, &filecontentB)
            if err != nil {
				return nil, err
			}
        }
    }
    return &filecontentB, nil
}


func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	FB, err := userdata.createOrGetFile(filename)
    if err != nil {
		return err
	}
	fileTK := FB.TK
    filenameC := FB.FilenameC
    chunk, err := makeChunk(content, &fileTK)
    if err != nil {
        return err
    }
    m := []Chunk {*chunk}
    marshalledChunk, err := json.Marshal(m)
    if err != nil {
        return err
    }
    userlib.DatastoreSet(filenameC, marshalledChunk)
    return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	filecontentB, err := userdata.createOrGetFile(filename)
    if err != nil {
		return err
	}
    filenameC := filecontentB.FilenameC
    chunk, err := makeChunk(content, &filecontentB.TK)
    if err != nil {
		return err
	}
    filecontent, ok := userlib.DatastoreGet(filenameC)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
    m := []Chunk{}
    err = json.Unmarshal(filecontent,  &m)
    if err != nil {
		return err
	}
    for _, chunk := range m {
        err = verifyChunk(chunk, filecontentB.TK)
        if err != nil {
            return errors.New(strings.ToTitle("corrupted file"))
        }
    }
    m = append(m, *chunk)
    marshalledChunk, err := json.Marshal(m)
    if err != nil {
		return err
	}
    userlib.DatastoreSet(filenameC, marshalledChunk)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
    FB, err := userdata.createOrGetFile(filename)
    if err != nil {
		return nil, err
	}
    filenameC := FB.FilenameC
    filecontent, ok := userlib.DatastoreGet(filenameC)
    if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
    m := []Chunk{}
    err = json.Unmarshal(filecontent,  &m)
    if err != nil {
		return nil, err
	}
    ret := []byte{}
    for _, chunk := range m {
        if err = verifyChunk(chunk, FB.TK); err != nil {
            return nil, errors.New(strings.ToTitle("corrupted file"))
        } else {
			content := userlib.SymDec(FB.TK.SymmKey, chunk.Content)
            ret = append(ret, content...)
        }
    }
    return ret, nil
}


type SharedMap struct {
	Content map[string]map[string][]byte
}

func CreateSharedMap() (*SharedMap, error) {
	var sharedmap SharedMap
	sharedmap.Content = make(map[string]map[string][]byte)
	return &sharedmap, nil
}

func (userdata *User) LoadSharedMap() (*SharedMap, error) {
	filename, err := hashUUID(userdata.FK.privkey_marshalled, "-sharedmap-")
	if err != nil {
		return nil, err
	}
	content, ok := userlib.DatastoreGet(filename)
	if !ok {
		return CreateSharedMap()
	}
	ret := &SharedMap{}
	err = json.Unmarshal(content, ret)
	return ret, err
}

func (userdata *User) SaveSharedMap(sharedmap *SharedMap) error {
	filename, err := hashUUID(userdata.FK.privkey_marshalled, "-sharedmap-")
	if err != nil {
		return err
	}
	content, err := json.Marshal(sharedmap)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(filename, content)
	return nil
}


type invitation struct {
	Nonce []byte
	Sig []byte
	OriginFilename string
}

func (userdata *User) ShareFile(filename string, recipientUsername string, N []byte) error {
	myfilenameB, err := hashUUID(userdata.FK.privkey_marshalled, "-file-", filename)
	if err != nil {
		return err
	}
    contentB, ok := userlib.DatastoreGet(myfilenameB)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	D, err := hashUUID("shared.", N, ".", userdata.Username, ".", recipientUsername, ".", filename)
	sharedmap, err := userdata.LoadSharedMap()
	if err != nil {
		return err
	}
	if sharedmap.Content[filename] == nil {
		sharedmap.Content[filename] = make(map[string][]byte)
	}
	sharedmap.Content[filename][recipientUsername] = N
	err = userdata.SaveSharedMap(sharedmap)
	if err != nil {
		return err
	}

	filenameB := uuid.New()
	userlib.DatastoreSet(filenameB, contentB)
	
	
	fileD := fileB{
		FilenameC: filenameB,
		TK: threekeys{},
		Typ: TYPE_RELAY,
	}
	contentD, err := json.Marshal(fileD)
	userlib.DatastoreSet(D, contentD)
	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	pubkeyTarget, ok := userlib.KeystoreGet(recipientUsername + ".pubkey")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("user not found"))
	}
	

	//
	// random nonce
	N := userlib.RandomBytes(48)
	err = userdata.ShareFile(filename, recipientUsername, N)
	if err != nil {
		return uuid.Nil, err
	}
	invitationuuid := uuid.New()
	
	encrypted, err := userlib.PKEEnc(pubkeyTarget, N)
	if err != nil {
		return uuid.Nil, err
	}
	signature, err := userlib.DSSign(userdata.FK.SignKey, encrypted)
	if err != nil {
		return uuid.Nil, err
	}
	invitation := invitation{
		Nonce: encrypted,
		Sig: signature,
		OriginFilename: filename,
	}
	json, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationuuid, json)
	return invitationuuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	content, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("invitation not found"))
	}
	invitation := invitation{}
	err := json.Unmarshal(content, &invitation)
	if err != nil {
		return err
	}
	Nonce := invitation.Nonce
	verifykey, ok := userlib.KeystoreGet(senderUsername + ".verifykey")
	if !ok {
		return errors.New(strings.ToTitle("sender not found"))
	}
	err = userlib.DSVerify(verifykey, Nonce, invitation.Sig);
	if err != nil {
		return errors.New(strings.ToTitle("signature verification failed"))
	}
	N, err := userlib.PKEDec(userdata.FK.PrivKey, Nonce)
	if err != nil {
		return err
	}
	D, err := hashUUID("shared.", N, ".", senderUsername, ".", userdata.Username, ".", invitation.OriginFilename)
	myfilenameB, err := hashUUID(userdata.FK.privkey_marshalled, "-file-", filename)
	if err != nil {
		return err
	}
	newFileB := fileB{
		FilenameC: D,
		TK: threekeys{},
		Typ: TYPE_RELAY,
	}
	
	
	saveContent, err := json.Marshal(newFileB)
	
	userlib.DatastoreSet(myfilenameB, saveContent)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	sharedmap, err := userdata.LoadSharedMap()
	if err != nil {
		return err
	}
	if sharedmap.Content[filename] == nil {
		return errors.New(strings.ToTitle("file not shared"))
	}
	delete(sharedmap.Content[filename], recipientUsername)
	myfilenameB, err := hashUUID(userdata.FK.privkey_marshalled, "-file-", filename)
	if err != nil {
		return err
	}
    contentB, ok := userlib.DatastoreGet(myfilenameB)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}

	fileB := fileB{}
	err = json.Unmarshal(contentB, &fileB)
	if err != nil {
		return err
	}
	newFilenameC := uuid.New()
	oldContent, ok := userlib.DatastoreGet(fileB.FilenameC); 
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	userlib.DatastoreSet(newFilenameC, oldContent)
	userlib.DatastoreSet(fileB.FilenameC, []byte{})
	fileB.FilenameC = newFilenameC
	saveContent, err := json.Marshal(fileB)
	userlib.DatastoreSet(myfilenameB, saveContent)

	

	for targetName := range sharedmap.Content[filename] {
		N := sharedmap.Content[filename][targetName]
		err = userdata.ShareFile(filename, targetName, N)
		if err != nil {
			return err
		}
	}
	err = userdata.SaveSharedMap(sharedmap)
	if err != nil {
		return err
	}
	return nil
}



