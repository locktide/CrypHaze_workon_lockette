// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: CHHashFileVPlain.proto

#ifndef PROTOBUF_CHHashFileVPlain_2eproto__INCLUDED
#define PROTOBUF_CHHashFileVPlain_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2004000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2004001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
// @@protoc_insertion_point(includes)

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_CHHashFileVPlain_2eproto();
void protobuf_AssignDesc_CHHashFileVPlain_2eproto();
void protobuf_ShutdownFile_CHHashFileVPlain_2eproto();

class MFNHashFilePlainProtobuf;

// ===================================================================

class MFNHashFilePlainProtobuf : public ::google::protobuf::Message {
 public:
  MFNHashFilePlainProtobuf();
  virtual ~MFNHashFilePlainProtobuf();
  
  MFNHashFilePlainProtobuf(const MFNHashFilePlainProtobuf& from);
  
  inline MFNHashFilePlainProtobuf& operator=(const MFNHashFilePlainProtobuf& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const MFNHashFilePlainProtobuf& default_instance();
  
  void Swap(MFNHashFilePlainProtobuf* other);
  
  // implements Message ----------------------------------------------
  
  MFNHashFilePlainProtobuf* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const MFNHashFilePlainProtobuf& from);
  void MergeFrom(const MFNHashFilePlainProtobuf& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // optional uint32 hash_length_bytes = 1;
  inline bool has_hash_length_bytes() const;
  inline void clear_hash_length_bytes();
  static const int kHashLengthBytesFieldNumber = 1;
  inline ::google::protobuf::uint32 hash_length_bytes() const;
  inline void set_hash_length_bytes(::google::protobuf::uint32 value);
  
  // repeated string hash_value = 2;
  inline int hash_value_size() const;
  inline void clear_hash_value();
  static const int kHashValueFieldNumber = 2;
  inline const ::std::string& hash_value(int index) const;
  inline ::std::string* mutable_hash_value(int index);
  inline void set_hash_value(int index, const ::std::string& value);
  inline void set_hash_value(int index, const char* value);
  inline void set_hash_value(int index, const char* value, size_t size);
  inline ::std::string* add_hash_value();
  inline void add_hash_value(const ::std::string& value);
  inline void add_hash_value(const char* value);
  inline void add_hash_value(const char* value, size_t size);
  inline const ::google::protobuf::RepeatedPtrField< ::std::string>& hash_value() const;
  inline ::google::protobuf::RepeatedPtrField< ::std::string>* mutable_hash_value();
  
  // @@protoc_insertion_point(class_scope:MFNHashFilePlainProtobuf)
 private:
  inline void set_has_hash_length_bytes();
  inline void clear_has_hash_length_bytes();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::google::protobuf::RepeatedPtrField< ::std::string> hash_value_;
  ::google::protobuf::uint32 hash_length_bytes_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];
  
  friend void  protobuf_AddDesc_CHHashFileVPlain_2eproto();
  friend void protobuf_AssignDesc_CHHashFileVPlain_2eproto();
  friend void protobuf_ShutdownFile_CHHashFileVPlain_2eproto();
  
  void InitAsDefaultInstance();
  static MFNHashFilePlainProtobuf* default_instance_;
};
// ===================================================================


// ===================================================================

// MFNHashFilePlainProtobuf

// optional uint32 hash_length_bytes = 1;
inline bool MFNHashFilePlainProtobuf::has_hash_length_bytes() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void MFNHashFilePlainProtobuf::set_has_hash_length_bytes() {
  _has_bits_[0] |= 0x00000001u;
}
inline void MFNHashFilePlainProtobuf::clear_has_hash_length_bytes() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void MFNHashFilePlainProtobuf::clear_hash_length_bytes() {
  hash_length_bytes_ = 0u;
  clear_has_hash_length_bytes();
}
inline ::google::protobuf::uint32 MFNHashFilePlainProtobuf::hash_length_bytes() const {
  return hash_length_bytes_;
}
inline void MFNHashFilePlainProtobuf::set_hash_length_bytes(::google::protobuf::uint32 value) {
  set_has_hash_length_bytes();
  hash_length_bytes_ = value;
}

// repeated string hash_value = 2;
inline int MFNHashFilePlainProtobuf::hash_value_size() const {
  return hash_value_.size();
}
inline void MFNHashFilePlainProtobuf::clear_hash_value() {
  hash_value_.Clear();
}
inline const ::std::string& MFNHashFilePlainProtobuf::hash_value(int index) const {
  return hash_value_.Get(index);
}
inline ::std::string* MFNHashFilePlainProtobuf::mutable_hash_value(int index) {
  return hash_value_.Mutable(index);
}
inline void MFNHashFilePlainProtobuf::set_hash_value(int index, const ::std::string& value) {
  hash_value_.Mutable(index)->assign(value);
}
inline void MFNHashFilePlainProtobuf::set_hash_value(int index, const char* value) {
  hash_value_.Mutable(index)->assign(value);
}
inline void MFNHashFilePlainProtobuf::set_hash_value(int index, const char* value, size_t size) {
  hash_value_.Mutable(index)->assign(
    reinterpret_cast<const char*>(value), size);
}
inline ::std::string* MFNHashFilePlainProtobuf::add_hash_value() {
  return hash_value_.Add();
}
inline void MFNHashFilePlainProtobuf::add_hash_value(const ::std::string& value) {
  hash_value_.Add()->assign(value);
}
inline void MFNHashFilePlainProtobuf::add_hash_value(const char* value) {
  hash_value_.Add()->assign(value);
}
inline void MFNHashFilePlainProtobuf::add_hash_value(const char* value, size_t size) {
  hash_value_.Add()->assign(reinterpret_cast<const char*>(value), size);
}
inline const ::google::protobuf::RepeatedPtrField< ::std::string>&
MFNHashFilePlainProtobuf::hash_value() const {
  return hash_value_;
}
inline ::google::protobuf::RepeatedPtrField< ::std::string>*
MFNHashFilePlainProtobuf::mutable_hash_value() {
  return &hash_value_;
}


// @@protoc_insertion_point(namespace_scope)

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_CHHashFileVPlain_2eproto__INCLUDED
