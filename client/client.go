package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

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

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	//Data store namespace uuid pointer
	NamespacePtr uuid.UUID
	//Key for symmetric file encryption
	PassKey []byte
	//Private PKE Key for decryption
	PKEKey userlib.PKEDecKey
	//Private signing key
	DSKey userlib.DSSignKey
	//Symmetric key to decrypt encrypt namespace
	NSKey []byte
	//Symmetric key to hmac namespace
	NSHmacKey []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	FileUid        uuid.UUID
	ShareTree      Tree
	ContentPointer uuid.UUID
}

type Tree struct {
	Username    string
	Children    []Tree
	InviteToken uuid.UUID
}

type Invitation struct {
	Sender    string
	Recipient string
	FileUID   uuid.UUID
	SymmKey   []byte
	HMACKey   []byte
}

type SigningPair struct {
	Data      []byte
	Signature []byte
}

type InviteSigning struct {
	Invitation   []byte
	InvitationDS []byte
	UnlockKey    []byte
	UnlockKeyDS  []byte
	Signer       string
}

type FileSigningPair struct {
	FileData           []byte
	FileHMAC           []byte
	ContentPointer     []byte
	ContentPointerHMAC []byte
}

const saltLen int = 16
const keyLen uint32 = 16
const key16 int = 16

const userSymmetricEncryptionHKDF = "symmetric encryption"
const hmacSigningHKDF = "hmac signing"
const fileEncrypt = "file encryption"
const fileHMAC = "file HMAC"
const publicPKE = "_pke"
const publicDS = "_ds"
const inviteDS = "invite DS"
const namespaceConst = "namespace"
const namespaceHmacConst = "namespace HMAC"

var shareExisted bool

// adding padding to byte array till it is a multiple of 16
func padTo16(data []byte) []byte {
	dLen := len(data)
	difference := 16 - (dLen % 16)
	diffSaved := difference
	var padded []byte = data
	for difference > 0 {
		// pad with # of bytes to be removed
		padding := []byte{byte(diffSaved)}
		padded = append(padded, padding[0])
		difference--

	}
	return padded

}

// remove padding of byte array
func removePadding(data []byte) []byte {
	//userlib.DebugMsg("REMOVE PADDING ERROR: %v", data)
	dLen := len(data)
	toRemove := int(data[dLen-1])
	return data[:dLen-toRemove]
}

// check if two byte arrays are equal
func byteEquals(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for x := range a {
		if a[x] != b[x] {
			return false
		}
	}
	return true
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//check if username already exists (if they already have a key in keystore?)
	usernamehash := userlib.Hash([]byte(username))
	usernameUUID := bytesToUUID(usernamehash[:])
	_, ok := userlib.DatastoreGet(usernameUUID)
	if ok {
		return nil, errors.New("username taken")
	}
	var userdata User
	userdataptr = &userdata

	// initialize fields in struct
	userdata.Username = username

	// initialize PKE and DS keys
	pubKeyPKE, privKeyPKE, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("failed to generate PKE keys")
	}
	signKeyDS, verifyKeyDS, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("failed to generate DS keys")
	}
	userdata.PKEKey = privKeyPKE
	userdata.DSKey = signKeyDS
	err = userlib.KeystoreSet(username+publicPKE, pubKeyPKE)
	if err != nil {
		return nil, errors.New("failed to store public PKE key")
	}
	err = userlib.KeystoreSet(username+publicDS, verifyKeyDS)
	if err != nil {
		return nil, errors.New("failed to store public DS key")
	}

	// generate pass_key
	passKey := userlib.Argon2Key([]byte(password), []byte(username), keyLen)
	userdata.PassKey = passKey
	symEncKey, err := userlib.HashKDF(passKey, []byte(userSymmetricEncryptionHKDF))
	if err != nil {
		// something failed so say something is bad
		return nil, errors.New("failed to Hash passKey")
	}
	hashedSymEncKey := userlib.Hash(symEncKey)

	//save symEncKey to  datastore
	passKeyHash := userlib.Hash([]byte(username + password))
	passkeyUUID := bytesToUUID(passKeyHash[:])
	userlib.DatastoreSet(passkeyUUID, []byte(hashedSymEncKey[:]))

	//NAMESPACE
	mapUUID := uuid.New()
	userdata.NamespacePtr = mapUUID
	namespace := make(map[string]uuid.UUID)
	namespaceKey, err := userlib.HashKDF(userdata.PassKey, []byte(namespaceConst))
	if err != nil {
		return nil, errors.New("failed to generate ns key")
	}
	userdata.NSKey = namespaceKey
	userdata.NSHmacKey, err = userlib.HashKDF(userdata.PassKey, []byte(namespaceHmacConst))
	if err != nil {
		return nil, errors.New("failed to generate ns hash key")
	}
	userdata.uploadNameSpace(namespace)
	// enc userdata
	iv := userlib.RandomBytes(key16)
	userAsByte, err := json.Marshal(userdata)
	if err != nil {
		// something failed
		return nil, errors.New("json Marshal of user failed")
	}
	userdataEnc := userlib.SymEnc(symEncKey[:16], iv, padTo16(userAsByte))

	// sign enc userdata
	hmacKey, err := userlib.HashKDF(passKey, []byte(hmacSigningHKDF))
	if err != nil {
		// something failed so say something is bad
		return nil, errors.New("hmac key derivation failed")
	}
	signed, err := userlib.HMACEval(hmacKey[:16], userdataEnc)
	if err != nil {
		// something failed so say something is bad
		return nil, errors.New("hmac signing failed")
	}

	var sp SigningPair
	sp.Data = userdataEnc
	sp.Signature = signed

	signingPairByte, err := json.Marshal(sp)
	if err != nil {
		return nil, errors.New("failed to marshal signed user pair")
	}

	// add to data store
	userlib.DatastoreSet(usernameUUID, signingPairByte)

	return &userdata, nil
}

func (userdata *User) uploadNameSpace(namespace map[string]uuid.UUID) (err error) {
	mapUUID := userdata.NamespacePtr
	nsIv := userlib.RandomBytes(key16)
	nsAsByte, err := json.Marshal(namespace)
	if err != nil {
		return errors.New("failed to marshal namespace")
	}
	encryptedNamespace := userlib.SymEnc(userdata.NSKey[:16], nsIv, padTo16(nsAsByte))
	nsHMAC, err := userlib.HMACEval(userdata.NSHmacKey[:16], encryptedNamespace)
	if err != nil {
		return errors.New("failed to HMAC namespace")
	}
	signPair := SigningPair{encryptedNamespace, nsHMAC}
	marshaledSignPair, err := json.Marshal(signPair)
	if err != nil {
		return errors.New("failed to marshal")
	}
	userlib.DatastoreSet(mapUUID, marshaledSignPair)
	return nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// get datastore at username
	usernameHash := userlib.Hash([]byte(username))
	usernameUUID := bytesToUUID(usernameHash[:])
	fetchedSigningPair, ok := userlib.DatastoreGet(usernameUUID)
	if !ok {
		// user does not exist
		return nil, errors.New("given user does not exist")
	}

	var sp SigningPair
	json.Unmarshal(fetchedSigningPair, &sp)

	fetchedUser := sp.Data
	hmacSigning := sp.Signature

	//fetch actual user passkey
	passKeyHash := userlib.Hash([]byte(username + password))
	passkeyUUID := bytesToUUID(passKeyHash[:])
	savedHashedSymEncKey, ok := userlib.DatastoreGet(passkeyUUID)
	if !ok {
		// symEncKey does not exist in store
		return nil, errors.New("user passKey not found")
	}

	// calculate user symEncKey
	givenPassKey := userlib.Argon2Key([]byte(password), []byte(username), keyLen)
	calcSymEncKey, err := userlib.HashKDF(givenPassKey, []byte(userSymmetricEncryptionHKDF))
	if err != nil {
		return nil, errors.New("something bad")
	}
	hashedGivenSymEncKey := userlib.Hash(calcSymEncKey)

	if !byteEquals([]byte(hashedGivenSymEncKey[:]), savedHashedSymEncKey) {
		// given password does not equal saved password
		return nil, errors.New("invalid Credentials for User Login")
	}

	// verify integrity of userstruct
	hmacKey, err := userlib.HashKDF(givenPassKey, []byte(hmacSigningHKDF))
	if err != nil {
		return nil, err
	}
	signed, err := userlib.HMACEval(hmacKey[:16], fetchedUser)
	if err != nil {
		return nil, err
	}

	match := userlib.HMACEqual(signed, hmacSigning)
	if !match {
		return nil, errors.New("userstruct tampering detected. Malicious attack evident")
	}

	// decrypt fetchedUser
	userdataStructJSON := removePadding(userlib.SymDec(calcSymEncKey[:16], fetchedUser))
	json.Unmarshal(userdataStructJSON, &userdata)

	return userdataptr, nil
}

func (userdata *User) fetchNamespace() (namespace map[string]uuid.UUID, err error) {
	marSigningStruct, ok := userlib.DatastoreGet(userdata.NamespacePtr)
	if !ok {
		return nil, errors.New("o namespace at this uuid")
	}
	var signPair SigningPair
	err = json.Unmarshal(marSigningStruct, &signPair)
	if err != nil {
		return nil, errors.New("failed to unmarshal")
	}
	enNamespace := signPair.Data
	namespaceJSON := removePadding(userlib.SymDec(userdata.NSKey[:16], enNamespace))
	json.Unmarshal(namespaceJSON, &namespace)
	//verify
	myHMAC, err := userlib.HMACEval(userdata.NSHmacKey[:16], enNamespace)
	if err != nil {
		return nil, errors.New("failed to compute hmac")
	}
	isEql := userlib.HMACEqual(myHMAC, signPair.Signature)
	if !isEql {
		return nil, errors.New("HMACs not equal")
	}
	return namespace, nil
}

func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	// check to see if file in namespace
	filePresent := false
	namespace, err := userdata.fetchNamespace()
	//userlib.DebugMsg("namespace in storefike: %s\n", namespace)
	if err != nil {
		return err
	}
	for fn, _ := range namespace { //filename, file id
		if fn == filename {
			filePresent = true
			//fileInvID := invID
			break
		}
	}
	// if file NOT in namespace do
	if !filePresent { // REVERT INVITE STRUCT

		// Create FILE encryption key
		encKey, err := userlib.HashKDF(userdata.PassKey, []byte(filename+userdata.Username+fileEncrypt))
		if err != nil {
			return errors.New("hkdf key gen failed for new store file")
		}

		// Create FILE hmac key
		hmacKey, err := userlib.HashKDF(userdata.PassKey, []byte(filename+userdata.Username+"fileHMAC"))
		if err != nil {
			return errors.New("hkdf key gen failed for new store file")
		}

		// Create access token UUID for INVITE
		accessKey := uuid.New()

		// Calculate FILE uuid
		fileID := uuid.New()

		// Create new FILE
		shareTree := Tree{userdata.Username, make([]Tree, 0), accessKey}

		// create file content struct
		nextPointer := uuid.Nil
		marshalPointer, err := json.Marshal(nextPointer)
		if err != nil {
			return errors.New("failed to marshal file content struct: " + err.Error())
		}
		iv := userlib.RandomBytes(key16)
		encryptedPointer := userlib.SymEnc(encKey[:16], iv, padTo16(marshalPointer))

		hmacPointer, err := userlib.HMACEval(hmacKey[:16], encryptedPointer)
		if err != nil {
			return errors.New("error computing hmac of enc file data")
		}

		// Encypt FILE data
		iv = userlib.RandomBytes(key16)
		encryptedData := userlib.SymEnc(encKey[:16], iv, padTo16(data))

		// Sign with hmac encrypted FILE data
		hmacSignature, err := userlib.HMACEval(hmacKey[:16], encryptedData)
		if err != nil {
			return errors.New("error computing hmac of enc file data")
		}

		// create new signing pair
		fileContentAccessToken := uuid.New()
		fileContentPair := FileSigningPair{encryptedData, hmacSignature, encryptedPointer, hmacPointer}
		fileContentPairMarshaled, err := json.Marshal(fileContentPair)
		if err != nil {
			return errors.New("failed to marshal file content pair")
		}
		userlib.DatastoreSet(fileContentAccessToken, fileContentPairMarshaled)

		// add access token for content to file list
		file := File{fileID, shareTree, fileContentAccessToken}

		// marshal full file struct
		fileMarshal, err := json.Marshal(file)
		if err != nil {
			return errors.New("failed to marshal file")
		}

		// encrypt full file content and compute hmac
		iv = userlib.RandomBytes(key16)
		encryptedFile := userlib.SymEnc(encKey[:16], iv, padTo16(fileMarshal))
		hmacFullSignature, err := userlib.HMACEval(hmacKey[:16], encryptedFile)
		if err != nil {
			return errors.New("error computing hmac of enc file data")
		}

		// create new file content pair

		fullFilePair := SigningPair{encryptedFile, hmacFullSignature}
		dsReadyFile, err := json.Marshal(fullFilePair)
		if err != nil {
			return errors.New("failed to marshal full enc hmac siging pair of file")
		}

		// Create sym enc key and hmac key for INVITE
		symInvEnc, err := userlib.HashKDF(userdata.PassKey, []byte("invitation encryption"))
		if err != nil {
			return errors.New("hkdf key gen failed for new store file")
		}
		symInvEnc = symInvEnc[:16]

		// Create INVITE struct
		myInvite := Invitation{userdata.Username, userdata.Username, fileID, encKey, hmacKey}

		// Marshal INVITE for encryption
		marshaledInvite, err := json.Marshal(myInvite)
		if err != nil {
			return errors.New("invite marshal failed for storefile")
		}

		// encrypt INVITE
		iv = userlib.RandomBytes(16)
		encryptedInvite := userlib.SymEnc(symInvEnc[:16], iv, padTo16(marshaledInvite))

		// Add INVITE uuid and FILE uuid to user maps
		namespace[filename] = accessKey
		userdata.uploadNameSpace(namespace)
		//userdata.TokensMap[filename] = accessKey
		//userdata.Namespace[filename] = fileID

		// Get asym public key for reciever to encrypt symKey for INVITE
		publicKey, ok := userlib.KeystoreGet(userdata.Username + publicPKE)
		if !ok {
			return errors.New("no public key for user")
		}

		// Encrypt the symKey for INVITE
		encryptedKey, err := userlib.PKEEnc(publicKey, symInvEnc[:16])
		if err != nil {
			return err
		}

		// Digitally Sign the symKey and the enc invite for INVITE
		myKey := userdata.DSKey
		dsSymKey, err := userlib.DSSign(myKey, encryptedKey)
		if err != nil {
			return errors.New("signing failed for new invite - store file")
		}
		dsInvite, err := userlib.DSSign(myKey, encryptedInvite)
		if err != nil {
			return err
		}

		// add enc symctric encryption key of INVITE to data store
		inviteHolder := InviteSigning{encryptedInvite, dsInvite, encryptedKey, dsSymKey, userdata.Username}

		marshaledInviteHolder, err := json.Marshal(inviteHolder)
		if err != nil {
			return errors.New("failed to marshal invite holder: " + err.Error())
		}

		//store file struct, invite signing struct, and invite in datastore
		userlib.DatastoreSet(accessKey, marshaledInviteHolder)
		userlib.DatastoreSet(fileID, dsReadyFile)

	} else { // if file in namespace   // REVERT INVITE STRUCT
		//get token fom tokens map
		accessKeyForInvite := namespace[filename]
		// get invite from datastore
		myInvite, err := fetchInvite(userdata, accessKeyForInvite)
		if err != nil {
			return err
		}
		// get key from token
		encKey := myInvite.SymmKey
		hmacKey := myInvite.HMACKey
		fileID := myInvite.FileUID
		// fetch file
		dsFile, ok := userlib.DatastoreGet(fileID)
		if !ok {
			return errors.New("file not found in datastore")
		}

		var fetchedFileSignPair SigningPair
		err = json.Unmarshal(dsFile, &fetchedFileSignPair)
		if err != nil {
			return err
		}

		encryptedFile := fetchedFileSignPair.Data

		// verify file
		calcdHMAC, err := userlib.HMACEval(hmacKey[:16], encryptedFile)
		if err != nil {
			return err
		}

		if !userlib.HMACEqual(calcdHMAC, fetchedFileSignPair.Signature) {
			return errors.New("file either tampered with or access not allowed")
		}

		// decrypt file
		regularFile := userlib.SymDec(encKey[:16], encryptedFile)
		regularFile = removePadding(regularFile)

		var fetchedFile File
		err = json.Unmarshal(regularFile, &fetchedFile)
		if err != nil {
			return err
		}

		// encrypt and hmac new data
		iv := userlib.RandomBytes(key16)
		encryptedData := userlib.SymEnc(encKey[:16], iv, padTo16(data))
		hmacSig, err := userlib.HMACEval(hmacKey[:16], encryptedData)
		if err != nil {
			return errors.New("failed to computer HMAC of file content")
		}

		// encrypt and hmac new nil pointer
		nextPointer := uuid.Nil
		marshalPointer, err := json.Marshal(nextPointer)
		if err != nil {
			return errors.New("faild to marshal pointer: " + err.Error())
		}
		iv = userlib.RandomBytes(key16)
		encryptedPointer := userlib.SymEnc(encKey[:16], iv, padTo16(marshalPointer))
		pointerSig, err := userlib.HMACEval(hmacKey[:16], encryptedPointer)
		if err != nil {
			return errors.New("failed to computer HMAC of file content")
		}

		// create new signing pair
		fileContentAccessToken := uuid.New()
		fileContentPair := FileSigningPair{encryptedData, hmacSig, encryptedPointer, pointerSig}
		fileContentPairMarshaled, err := json.Marshal(fileContentPair)
		if err != nil {
			return errors.New("failed to marshal file content pair")
		}
		userlib.DatastoreSet(fileContentAccessToken, fileContentPairMarshaled)

		// add access token for content to file pointer
		fetchedFile.ContentPointer = fileContentAccessToken

		// marshal full file
		marshaledFullFile, err := json.Marshal(fetchedFile)
		if err != nil {
			return errors.New("failed to marshal full file")
		}

		// encrypt full file
		iv = userlib.RandomBytes(16)
		encryptFullFile := userlib.SymEnc(encKey[:16], iv, padTo16(marshaledFullFile))

		//sign
		hmacSignature, err := userlib.HMACEval(hmacKey[:16], encryptFullFile)
		if err != nil {
			return errors.New("error computing hmac of enc file data")
		}

		// create file, hmac pair
		fileSigningPair := SigningPair{encryptFullFile, hmacSignature}

		// remarshal for saving
		remarshal, err := json.Marshal(fileSigningPair)
		if err != nil {
			// error check
			return errors.New("failed to marshal new file")
		}

		// store marshal file in dataStore
		userlib.DatastoreSet(fileID, remarshal)

	}

	return nil
}

func fetchInvite(user *User, accessKey uuid.UUID) (invite Invitation, err error) { // REVERT INVITE STRUCT
	// get invite from datastore
	marshaledInviteHolder, ok := userlib.DatastoreGet(accessKey)
	if !ok {
		return Invitation{}, errors.New("access key not in datastore")
	}

	var inviteHolder InviteSigning
	err = json.Unmarshal(marshaledInviteHolder, &inviteHolder)
	if err != nil {
		return Invitation{}, errors.New("failed to unmarshal invite holder")
	}

	inviteDecKeyEnc := inviteHolder.UnlockKey //key used to unlock invitation, encrypted
	//validate key used to unlock invite
	signer := inviteHolder.Signer
	signerPubKey, ok := userlib.KeystoreGet(signer + "_ds")
	if !ok {
		return Invitation{}, errors.New("public key not found")
	}
	err = userlib.DSVerify(signerPubKey, inviteDecKeyEnc, inviteHolder.UnlockKeyDS)
	if err != nil {
		return Invitation{}, errors.New("failed to verify key used to unlock invite")
	}
	privKey := user.PKEKey
	//decrypt key used to unlock invitation
	symDecKey, err := userlib.PKEDec(privKey, inviteDecKeyEnc) //key used to unlock invitation
	if err != nil {
		return Invitation{}, errors.New("failed to decrypt invite sym key")
	}
	//validate invite
	encryptedInvite := inviteHolder.Invitation
	err = userlib.DSVerify(signerPubKey, encryptedInvite, inviteHolder.InvitationDS)
	if err != nil {
		return Invitation{}, errors.New("failed to verify invite")
	}
	//decrypt invite
	decInvite := userlib.SymDec(symDecKey[:16], encryptedInvite)
	decInvite = removePadding(decInvite)
	var myInvite Invitation
	json.Unmarshal(decInvite, &myInvite)

	return myInvite, nil
}

// AppendFile
func (userdata *User) AppendToFile(filename string, data []byte) (err error) {

	// get fileID
	namespace, err := userdata.fetchNamespace()
	if err != nil {
		return err
	}
	var filePresent bool
	var accessToken uuid.UUID
	for fn, at := range namespace { //filename, file id
		if fn == filename {
			filePresent = true
			accessToken = at
			break
		}
	}
	if !filePresent {
		return errors.New("file not found in namespace")
	}

	// get invite to file
	invite, err := fetchInvite(userdata, accessToken)
	if err != nil {
		return err
	}

	// confirm file untampered --VERIFY FILE
	hmacKey := invite.HMACKey
	fileID := invite.FileUID
	// download file from datastore
	fetchedFile, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return errors.New("fileID not found in data store")
	}

	var fileSigningPair SigningPair
	json.Unmarshal(fetchedFile, &fileSigningPair)

	// decrypt file
	encKey := invite.SymmKey
	decFile := userlib.SymDec(encKey[:16], fileSigningPair.Data)
	decFile = removePadding(decFile)

	var file File
	json.Unmarshal(decFile, &file)

	//I AM HERE
	// START DEBUG
	var accessor string
	if file.ShareTree.Username == userdata.Username {
		accessor = userdata.Username
	}

	for i, s := range file.ShareTree.Children {
		fmt.Print(i, s)
		if s.Username == userdata.Username {
			accessor = s.Username
		}
	}
	if len(accessor) == 0 {
		return errors.New("This user is not in the file's sharetree")
	}
	//END DEBUG

	// enc new data
	iv := userlib.RandomBytes(16)
	encData := userlib.SymEnc(encKey[:16], iv, padTo16(data))

	// encrypt and hmac old id
	currentPointer := file.ContentPointer
	marshalPointer, err := json.Marshal(currentPointer)
	if err != nil {
		return errors.New("failed to marshal content pointer: " + err.Error())
	}
	iv = userlib.RandomBytes(16)
	encPointer := userlib.SymEnc(encKey[:16], iv, padTo16(marshalPointer))

	hmacPointer, err := userlib.HMACEval(hmacKey[:16], encPointer)
	if err != nil {
		return errors.New("failed to hmac new file content")
	}

	// create new file content pair
	digSigConent, err := userlib.HMACEval(hmacKey[:16], encData)
	if err != nil {
		return errors.New("failed to hmac new file content")
	}
	fileContentPair := FileSigningPair{encData, digSigConent, encPointer, hmacPointer}
	dsReadyContent, err := json.Marshal(fileContentPair)
	if err != nil {
		return errors.New("failed to marshal file content signing pair")
	}

	// generate new content access token
	newContentPointer := uuid.New()
	file.ContentPointer = newContentPointer

	// sign and encrypt updated file
	fileStruct, err := json.Marshal(file)
	if err != nil {
		return errors.New("failed to marshal file struct")
	}

	iv = userlib.RandomBytes(16)
	fileStructEnc := userlib.SymEnc(encKey[:16], iv, padTo16(fileStruct))

	digSig, err := userlib.HMACEval(hmacKey[:16], fileStructEnc)
	if err != nil {
		return errors.New("failed to HMAC enc file struct")
	}

	// create new file sig pair
	newFileSignPair := SigningPair{fileStructEnc, digSig}

	fileFinal, err := json.Marshal(newFileSignPair)
	if err != nil {
		return errors.New("failed to marshal file sig pair")
	}

	// send file back to datastore
	userlib.DatastoreSet(fileID, fileFinal)
	userlib.DatastoreSet(newContentPointer, dsReadyContent)

	return nil
}

func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	namespace, err := userdata.fetchNamespace()
	if err != nil {
		return nil, err
	}

	//download invite
	oldAccessToken, ok := namespace[filename]
	if !ok {
		return nil, errors.New("file not present in user namespace")
	}
	oldInvite, err := fetchInvite(userdata, oldAccessToken)
	if err != nil {
		return nil, err
	}
	fileID := oldInvite.FileUID
	encKey := oldInvite.SymmKey
	hmacKey := oldInvite.HMACKey

	// get file
	loadedFile, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return nil, errors.New("file not found in datastore")
	}

	// unmarshal signing pair
	var loadedFileSigningPair SigningPair
	json.Unmarshal(loadedFile, &loadedFileSigningPair)

	// verify HMAC
	currSig := loadedFileSigningPair.Signature
	currContent := loadedFileSigningPair.Data
	//userlib.DebugMsg("CURR CONTENT :  %v", currContent)
	evaledSig, err := userlib.HMACEval(hmacKey[:16], currContent)
	if err != nil {
		return nil, errors.New("failed to evalute hmac of encrypted file")
	}
	if !userlib.HMACEqual(currSig, evaledSig) {
		return nil, errors.New("HMAC signature verification failed, tampering possible")
	}

	//decrypt file
	decryptedFile := userlib.SymDec(encKey[:16], currContent)
	decryptedFile = removePadding(decryptedFile)

	var fileFull File
	json.Unmarshal(decryptedFile, &fileFull)

	fileContent := make([]byte, 0)
	cp := fileFull.ContentPointer

	for cp != uuid.Nil {
		fetchedContent, ok := userlib.DatastoreGet(cp)
		if !ok {
			return nil, errors.New("failed to fetch file content @ token")
		}
		var contentPair FileSigningPair
		json.Unmarshal(fetchedContent, &contentPair)

		fileSnippet := contentPair.FileData
		sig := contentPair.FileHMAC

		calcdSig, err := userlib.HMACEval(hmacKey[:16], fileSnippet)
		if err != nil {
			return nil, errors.New("failed to HMAC file contents")
		}

		if !userlib.HMACEqual(sig, calcdSig) {
			return nil, errors.New("failed to verify file contents, tampering possible")
		}

		dec := userlib.SymDec(encKey[:16], fileSnippet)
		dec = removePadding(dec)
		fileContent = append(dec, fileContent[:]...)

		nextPointer := contentPair.ContentPointer
		pointerSig := contentPair.ContentPointerHMAC

		calcdPSig, err := userlib.HMACEval(hmacKey[:16], nextPointer)
		if err != nil {
			return nil, errors.New("failed to HMAC file pointer")
		}

		if !userlib.HMACEqual(pointerSig, calcdPSig) {
			return nil, errors.New("failed to verify file pointer, tampering possible")
		}

		decPointer := userlib.SymDec(encKey[:16], nextPointer)
		decPointer = removePadding(decPointer)
		var pointerID uuid.UUID
		json.Unmarshal(decPointer, &pointerID)

		cp = pointerID

	}

	return fileContent, nil
}

// func (userdata *User) CreateInvitation(filename string, recipient string) (
// 	accessToken uuid.UUID, err error) {
// 	// create bad uuid
// 	errUUID := uuid.Nil
// 	namespace, err := userdata.fetchNamespace()
// 	if err != nil {
// 		return uuid.Nil, err
// 	}

// 	// fetch encKey from their invitation from filename
// 	oldAccessToken, ok := namespace[filename]
// 	if !ok {
// 		return uuid.Nil, errors.New("file not present in user namespace")
// 	}
// 	oldInvite, err := fetchInvite(userdata, oldAccessToken)
// 	if err != nil {
// 		return errUUID, err
// 	}
// 	encKey := oldInvite.SymmKey
// 	hmacKey := oldInvite.HMACKey
// 	// fetch fileID from userdata namespace
// 	fileID := oldInvite.FileUID
// 	newInvite := Invitation{userdata.Username, recipient, fileID, encKey, hmacKey}

// 	// marshal invite for enc
// 	marshalInvite, err := json.Marshal(newInvite)
// 	if err != nil {
// 		return uuid.Nil, errors.New("failed to marshal invite") //TODO: replace w/ uuid.nil?
// 	}

// 	// get recipients public key from keystore
// 	pubPKE, ok := userlib.KeystoreGet(recipient + "_pke")
// 	if !ok {
// 		return errUUID, errors.New("public key of recipient not found")
// 	}

// 	// create new sym key invite pointer
// 	symInvKey, err := userlib.HashKDF(userdata.PassKey, []byte("invitation encryption"))
// 	if err != nil {
// 		return errUUID, errors.New("failed to generate invite symmteric encryption key")
// 	}

// 	// ecrypt invite
// 	iv := userlib.RandomBytes(16)
// 	encInvite := userlib.SymEnc(symInvKey[:16], iv, padTo16(marshalInvite))

// 	// encrypt symkey
// 	encInviteKey, err := userlib.PKEEnc(pubPKE, symInvKey)
// 	if err != nil {
// 		return errUUID, errors.New("failed to encrypt invite access key")
// 	}

// 	// get userdata private key for signing
// 	signKey := userdata.DSKey

// 	// sign above keys and invite
// 	dsInvKey, err := userlib.DSSign(signKey, encInviteKey)
// 	if err != nil {
// 		return errUUID, errors.New("failed to sign new key")
// 	}
// 	dsInv, err := userlib.DSSign(signKey, encInvite)
// 	if err != nil {
// 		return errUUID, errors.New("failed to sign enc invite")
// 	}

// 	// create accessToken for invite holder
// 	accessToken = uuid.New()
// 	newInvSignHolder := InviteSigning{encInvite, dsInv, encInviteKey, dsInvKey, userdata.Username}

// 	// get file
// 	fetchedFile, ok := userlib.DatastoreGet(fileID)
// 	if !ok {
// 		return errUUID, errors.New("failed to fetch file from file ID")
// 	}

// 	// unmarshal file
// 	var fileSignPair SigningPair
// 	json.Unmarshal(fetchedFile, &fileSignPair)

// 	// verify file struct
// 	calcSig, err := userlib.HMACEval(hmacKey[:16], fileSignPair.Data)
// 	if err != nil {
// 		return errUUID, errors.New("failed to calculate hmac of returned file sign pair data")
// 	}
// 	if !userlib.HMACEqual(fileSignPair.Signature, calcSig) {
// 		return errUUID, errors.New("file struct HMAC does not match, tampering possible")
// 	}

// 	// dec file struct
// 	fileStruct := userlib.SymDec(encKey[:16], fileSignPair.Data)
// 	fileStruct = removePadding(fileStruct)

// 	var file File
// 	json.Unmarshal(fileStruct, &file)

// 	// get sharetree
// 	st := file.ShareTree
// 	// update shareTree
// 	newShareTree := addNodeShareTree(st, userdata.Username, recipient, accessToken)
// 	file.ShareTree = newShareTree

// 	//enc file
// 	remarshal, err := json.Marshal(file)
// 	if err != nil {
// 		return errUUID, errors.New("failed to remarshal invite after share tree")
// 	}

// 	iv = userlib.RandomBytes(key16)
// 	encryptedFileStruct := userlib.SymEnc(encKey[:16], iv, padTo16(remarshal))

// 	//create new signing pair
// 	newFileSig, err := userlib.HMACEval(hmacKey[:16], encryptedFileStruct)
// 	if err != nil {
// 		return errUUID, errors.New("failed to hmac new encrypted file struct")
// 	}
// 	newFileSignPair := SigningPair{encryptedFileStruct, newFileSig}

// 	dsReadyFile, err := json.Marshal(newFileSignPair)
// 	if err != nil {
// 		return errUUID, errors.New("failed to marshal final file singing pair")
// 	}

// 	// save to datastore
// 	readyInvitation, err := json.Marshal(newInvSignHolder)
// 	if err != nil {
// 		return errUUID, errors.New("failed to marshal full invitiation")
// 	}
// 	userlib.DatastoreSet(fileID, dsReadyFile)
// 	userlib.DatastoreSet(accessToken, readyInvitation)

// 	return accessToken, nil
// }

func (userdata *User) CreateInvitation(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	// create bad uuid
	errUUID := uuid.Nil
	namespace, err := userdata.fetchNamespace()
	if err != nil {
		return uuid.Nil, err
	}

	// fetch encKey from their invitation from filename
	oldAccessToken, ok := namespace[filename]
	if !ok {
		return uuid.Nil, errors.New("file not present in user namespace")
	}
	oldInvite, err := fetchInvite(userdata, oldAccessToken)
	if err != nil {
		return errUUID, err
	}
	encKey := oldInvite.SymmKey
	hmacKey := oldInvite.HMACKey
	// fetch fileID from userdata namespace
	fileID := oldInvite.FileUID
	// if !ok {
	// 	return errUUID, errors.New("cannot find file in user namespace") //TODO: replace w/ uuid.nil?
	// }
	// create new invitation
	newInvite := Invitation{userdata.Username, recipient, fileID, encKey, hmacKey}

	// marshal invite for enc
	marshalInvite, err := json.Marshal(newInvite)
	if err != nil {
		return uuid.Nil, errors.New("failed to marshal invite") //TODO: replace w/ uuid.nil?
	}

	// get recipients public key from keystore
	pubPKE, ok := userlib.KeystoreGet(recipient + "_pke")
	if !ok {
		return errUUID, errors.New("public key of recipient not found")
	}

	// create new sym key invite pointer
	symInvKey, err := userlib.HashKDF(userdata.PassKey, []byte("invitation encryption"))
	if err != nil {
		return errUUID, errors.New("failed to generate invite symmteric encryption key")
	}

	// ecrypt invite
	iv := userlib.RandomBytes(16)
	encInvite := userlib.SymEnc(symInvKey[:16], iv, padTo16(marshalInvite))

	// encrypt symkey
	encInviteKey, err := userlib.PKEEnc(pubPKE, symInvKey)
	if err != nil {
		return errUUID, errors.New("failed to encrypt invite access key")
	}

	// get userdata private key for signing
	signKey := userdata.DSKey

	// sign above keys and invite
	dsInvKey, err := userlib.DSSign(signKey, encInviteKey)
	if err != nil {
		return errUUID, errors.New("failed to sign new key")
	}
	dsInv, err := userlib.DSSign(signKey, encInvite)
	if err != nil {
		return errUUID, errors.New("failed to sign enc invite")
	}

	// create accessToken for invite holder
	accessToken = uuid.New()
	newInvSignHolder := InviteSigning{encInvite, dsInv, encInviteKey, dsInvKey, userdata.Username}

	// get file
	fetchedFile, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return errUUID, errors.New("failed to fetch file from file ID")
	}

	// unmarshal file
	var fileSignPair SigningPair
	json.Unmarshal(fetchedFile, &fileSignPair)

	// verify file struct
	calcSig, err := userlib.HMACEval(hmacKey[:16], fileSignPair.Data)
	if err != nil {
		return errUUID, errors.New("failed to calculate hmac of returned file sign pair data")
	}
	if !userlib.HMACEqual(fileSignPair.Signature, calcSig) {
		return errUUID, errors.New("file struct HMAC does not match, tampering possible")
	}

	// dec file struct
	fileStruct := userlib.SymDec(encKey[:16], fileSignPair.Data)
	fileStruct = removePadding(fileStruct)

	var file File
	json.Unmarshal(fileStruct, &file)

	// get sharetree
	st := file.ShareTree
	// update shareTree
	newShareTree := addNodeShareTree(st, userdata.Username, recipient, accessToken)
	file.ShareTree = newShareTree

	//enc file
	remarshal, err := json.Marshal(file)
	if err != nil {
		return errUUID, errors.New("failed to remarshal invite after share tree")
	}

	iv = userlib.RandomBytes(key16)
	encryptedFileStruct := userlib.SymEnc(encKey[:16], iv, padTo16(remarshal))

	//create new signing pair
	newFileSig, err := userlib.HMACEval(hmacKey[:16], encryptedFileStruct)
	if err != nil {
		return errUUID, errors.New("failed to hmac new encrypted file struct")
	}
	newFileSignPair := SigningPair{encryptedFileStruct, newFileSig}

	dsReadyFile, err := json.Marshal(newFileSignPair)
	if err != nil {
		return errUUID, errors.New("failed to marshal final file singing pair")
	}

	// save to datastore
	readyInvitation, err := json.Marshal(newInvSignHolder)
	if err != nil {
		return errUUID, errors.New("failed to marshal full invitiation")
	}
	userlib.DatastoreSet(fileID, dsReadyFile)
	userlib.DatastoreSet(accessToken, readyInvitation)

	return accessToken, nil
}

// Update sharing tree
func addNodeShareTree(tree Tree, username string, recipient string, recipientToken uuid.UUID) Tree {
	var newTree Tree
	newTree.Username = tree.Username
	newTree.InviteToken = tree.InviteToken
	if username == tree.Username {
		// i have found the node
		newChild := Tree{recipient, make([]Tree, 0), recipientToken}
		children := append(tree.Children, newChild)
		newTree.Children = children
		return newTree
	} else {
		// i have not found the node
		children := make([]Tree, 0)
		for ch := range tree.Children {
			newChild := addNodeShareTree(tree.Children[ch], username, recipient, recipientToken)
			children = append(children, newChild)
		}
		newTree.Children = children
		return newTree
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	namespace, err := userdata.fetchNamespace()
	if err != nil {
		return err
	}
	myInvite, err := fetchInvite(userdata, invitationPtr)
	if err != nil {
		return err //fetchinvite will return err if invite not at accesstoken, aka if invite was revoked
	}
	fileID := myInvite.FileUID

	//error if recipient already has file with given filename, or already has file, in namespace
	for fn, at := range namespace { //filename, file id
		if fn == filename {
			return errors.New("file with given filename already exists")
		}
		//now we have to decrypt every invite to check the file id ooops....
		currInvite, err := fetchInvite(userdata, at)
		if err != nil {
			return err
		}
		if currInvite.FileUID == fileID {
			return errors.New("file with given file id already exists")
		}
	}
	// verify correct recipient
	if userdata.Username != myInvite.Recipient {
		return errors.New("decrypted by incorrect recipient")
	}

	//verify invite actually from sender
	if senderUsername != myInvite.Sender {
		return errors.New("unable to verify if given by actual sender")
	}
	//integrity verification done in fetchInvite

	namespace[filename] = invitationPtr
	err = userdata.uploadNameSpace(namespace)
	if err != nil {
		return errors.New("failed to update namespace")
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, targetUsername string) (err error) {
	// get file
	shareExisted = false
	namespace, err := userdata.fetchNamespace()
	if err != nil {
		return err
	}
	// get invite w/ hmac key --VERIFY INVITE
	inviteAccessToken, ok := namespace[filename]
	if !ok {
		return errors.New("file not found in user token map")
	}
	ownerInvite, err := fetchInvite(userdata, inviteAccessToken)
	if err != nil {
		return err
	}
	fileID := ownerInvite.FileUID

	fetchedFile, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return errors.New("fileID not found in datastore")
	}
	hmacKey := ownerInvite.HMACKey
	encKey := ownerInvite.SymmKey

	// unwrap file
	var fetchedFileHolder SigningPair
	json.Unmarshal(fetchedFile, &fetchedFileHolder)

	// verify file
	calcFileSig, err := userlib.HMACEval(hmacKey[:16], fetchedFileHolder.Data)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(calcFileSig, fetchedFileHolder.Signature) {
		return errors.New("hmac of file down not match, cannot revoke user")
	}

	// decrypt file
	decryptdFileStruct := userlib.SymDec(encKey[:16], fetchedFileHolder.Data)
	decryptdFileStruct = removePadding(decryptdFileStruct)

	var file File
	err = json.Unmarshal(decryptdFileStruct, &file)
	if err != nil {
		return errors.New("failed to unmarshal file encryption")
	}

	//check to make sure they're file owner
	st := file.ShareTree
	owner := st.Username
	if userdata.Username != owner {
		return errors.New("user not allowed to revoke permissions")
	}

	// change enc key and hmac key
	newEncKey, err := userlib.HashKDF(userdata.PassKey, userlib.RandomBytes(16))
	if err != nil {
		return errors.New("failed to generate new HKDF enc key")
	}

	newHMACKey, err := userlib.HashKDF(userdata.PassKey, userlib.RandomBytes(16))
	if err != nil {
		return errors.New("failed to generate new HKDF HMAC key")
	}

	cp := file.ContentPointer

	// decrypt, verify and re-encrypt all file content
	for cp != uuid.Nil {
		// get fetched content
		fetchedContent, ok := userlib.DatastoreGet(cp)
		if !ok {
			return errors.New("failed to fetch file content @ token")
		}
		// load into file sign pair
		var contentPair FileSigningPair
		json.Unmarshal(fetchedContent, &contentPair)

		fileSnippet := contentPair.FileData
		sig := contentPair.FileHMAC

		// verify untampered
		calcdSig, err := userlib.HMACEval(hmacKey[:16], fileSnippet)
		if err != nil {
			return errors.New("failed to HMAC file contents")
		}

		if !userlib.HMACEqual(sig, calcdSig) {
			return errors.New("failed to verify file contents, tampering possible")
		}

		// decrypt file contents
		dec := userlib.SymDec(encKey[:16], fileSnippet)
		dec = removePadding(dec)

		// encrypt file contents
		iv := userlib.RandomBytes(16)
		enc := userlib.SymEnc(newEncKey[:16], iv, padTo16(dec))

		// hmac file contents
		hmac, err := userlib.HMACEval(newHMACKey[:16], enc)
		if err != nil {
			return errors.New("failed to hmac with new hmac key")
		}

		// get pointer and pointer sig
		nextPointer := contentPair.ContentPointer
		pointerSig := contentPair.ContentPointerHMAC

		// verify untampered pointer
		calcdPointerSig, err := userlib.HMACEval(hmacKey[:16], nextPointer)
		if err != nil {
			return errors.New("failed to HMAC file pointer")
		}

		if !userlib.HMACEqual(pointerSig, calcdPointerSig) {
			return errors.New("failed to verify file pointer, tampering possible")
		}

		// decrypt file pointer
		decP := userlib.SymDec(encKey[:16], nextPointer)
		decP = removePadding(decP)

		// encrypt file pointer
		iv = userlib.RandomBytes(16)
		encP := userlib.SymEnc(newEncKey[:16], iv, padTo16(decP))

		// hmac file pointer
		hmacP, err := userlib.HMACEval(newHMACKey[:16], encP)
		if err != nil {
			return errors.New("failed to hmac with new hmac key")
		}

		// create new FileSigningPair
		newFilePair := FileSigningPair{enc, hmac, encP, hmacP}
		dsReadyFP, err := json.Marshal(newFilePair)
		if err != nil {
			return errors.New("failed to marshal new file pair")
		}

		// reset file signing pair
		userlib.DatastoreSet(cp, dsReadyFP)

		var nextPointerUID uuid.UUID
		json.Unmarshal(removePadding(decP), &nextPointer)

		cp = nextPointerUID

	}

	// clip tree of revoked users
	removedShareTree := removeNodeShareTree(targetUsername, st)
	file.ShareTree = removedShareTree
	//Return error if no user removed (aka the given user not in tree, aka file wasn't shared with them)
	if !shareExisted {
		return errors.New("file was never shared with user")
	}
	// create new invite for everyone
	err = CreateInvitation(newEncKey, newHMACKey, removedShareTree, userdata.Username, fileID, userdata)
	if err != nil {
		return errors.New("failed to create new invites: " + err.Error())
	}

	// re-ecnrypt and hmac external file
	marshaledFile, err := json.Marshal(file)
	if err != nil {
		return errors.New("failed to marshal file struct: " + err.Error())
	}

	iv := userlib.RandomBytes(16)
	encNewFile := userlib.SymEnc(newEncKey[:16], iv, padTo16(marshaledFile))

	hmacNewFile, err := userlib.HMACEval(newHMACKey[:16], encNewFile)
	if err != nil {
		return err
	}

	// create new file signing pair
	updatedFile := SigningPair{encNewFile, hmacNewFile}
	dsReadyNewFile, err := json.Marshal(updatedFile)
	if err != nil {
		return err
	}

	// store new file
	userlib.DatastoreSet(fileID, dsReadyNewFile)

	return nil
}

func CreateInvitation(newEncKey []byte, newHMACKey []byte, shareTree Tree, parent string, fileID userlib.UUID, owner *User) error {
	// get user invite
	username := shareTree.Username

	// create new invite
	newInvitation := Invitation{parent, username, fileID, newEncKey, newHMACKey}

	// get recipients public key from keystore

	pubPKE, ok := userlib.KeystoreGet(username + publicPKE) //"_pke")
	if !ok {
		return errors.New("public key of recipient not found")
	}

	// get and encrypt symmetric encryption key
	symInvEnc, err := userlib.HashKDF(owner.PassKey, userlib.RandomBytes(16))
	if err != nil {
		return errors.New("failed to generate invite symmteric encryption key")
	}
	symInvEnc = symInvEnc[:16]

	encInviteKey, err := userlib.PKEEnc(pubPKE, symInvEnc)
	if err != nil {
		return errors.New("failed to encrypt invite access key")
	}

	// ecnrypt invite
	marshalInvite, err := json.Marshal(newInvitation)
	if err != nil {
		return errors.New("failed to marshal newInvite")
	}

	iv := userlib.RandomBytes(16)
	encInvite := userlib.SymEnc(symInvEnc[:16], iv, padTo16(marshalInvite))

	// digitally sign invite and key
	myDSKey := owner.DSKey
	inviteDS, err := userlib.DSSign(myDSKey, encInvite)
	if err != nil {
		return errors.New("failed to sign enc invite")
	}
	keyDS, err := userlib.DSSign(myDSKey, encInviteKey)
	if err != nil {
		return errors.New("failed to sign enc invite")
	}

	// create new invite signing holder with owner as signer
	inviteSigningHolder := InviteSigning{encInvite, inviteDS, encInviteKey, keyDS, owner.Username}

	// marshal sig holder
	fullInvite, err := json.Marshal(inviteSigningHolder)
	if err != nil {
		return errors.New("failed to marshal new invite")
	}

	// restore invite
	userlib.DatastoreSet(shareTree.InviteToken, fullInvite)

	for c := range shareTree.Children {
		child := shareTree.Children[c]
		err = CreateInvitation(newEncKey, newHMACKey, child, username, fileID, owner)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeNodeShareTree(removedUser string, tree Tree) Tree {
	var newTree Tree
	newTree.Username = tree.Username
	newTree.InviteToken = tree.InviteToken

	newChildren := make([]Tree, 0)
	removedFound := false

	for c := range tree.Children {
		child := tree.Children[c]
		if child.Username == removedUser {
			removedFound = true
			//delete invitation at revokee's token
			shareExisted = true
			userlib.DatastoreDelete(child.InviteToken)
		} else {
			newChildren = append(newChildren, child)
		}
	}

	if removedFound {
		newTree.Children = newChildren
		return newTree
	} else {
		finalChildren := make([]Tree, 0)
		for c := range tree.Children {
			child := tree.Children[c]
			childTree := removeNodeShareTree(removedUser, child)
			finalChildren = append(finalChildren, childTree)
		}
		newTree.Children = finalChildren
		return newTree
	}
}

// func (userdata *User) StoreFile(filename string, content []byte) (err error) {
// 	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
// 	if err != nil {
// 		return err
// 	}
// 	contentBytes, err := json.Marshal(content)
// 	if err != nil {
// 		return err
// 	}
// 	userlib.DatastoreSet(storageKey, contentBytes)
// 	return
// }

// func (userdata *User) AppendToFile(filename string, content []byte) error {
// 	return nil
// }

// func (userdata *User) LoadFile(filename string) (content []byte, err error) {
// 	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
// 	if err != nil {
// 		return nil, err
// 	}
// 	dataJSON, ok := userlib.DatastoreGet(storageKey)
// 	if !ok {
// 		return nil, errors.New(strings.ToTitle("file not found"))
// 	}
// 	err = json.Unmarshal(dataJSON, &content)
// 	return content, err
// }

// func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
// 	invitationPtr uuid.UUID, err error) {
// 	return
// }

// func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
// 	return nil
// }

// func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
// 	return nil
// }
