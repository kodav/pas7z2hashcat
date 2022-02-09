program pas7z2hashcat;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  WinApi.Windows,
  System.Classes,
  Generics.Collections,
  AbLZMA in 'LZMA\AbLZMA.pas';

const
  UNDEF = -1; // MaxInt;

  LZMA_DICT_SIZE_MIN = 4096;
  LZMA_STREAM_END = 1;

  ANALYZE_ALL_STREAMS_TO_FIND_SHORTEST_DATA_BUF = 1;

  SHOW_LIST_OF_ALL_STREAMS = 0; // $ANALYZE_ALL_STREAMS_TO_FIND_SHORTEST_DATA_BUF must be set to 1 to list/debug all streams
  SHOW_LZMA_DECOMPRESS_AFTER_DECRYPT_WARNING = 1;

  SHORTEN_HASH_LENGTH_TO_CRC_LENGTH = 1; // only output the bytes needed for the checksum of the first file (plus a fixed length
  // header at the very beginning of the stream; plus additional +5% to cover the exception
  // that the compressed file is slightly longer than the raw file)

  SHORTEN_HASH_FIXED_HEADER = 32.5; // at the beginning of the compressed stream we have some header info
  // (shortened hash can't really be shorter than the metadata needed for decompression)
  // the extra +0.5 is used to round up (we use integer numbers)
  SHORTEN_HASH_EXTRA_PERCENT = 5; // the compressed stream could be slightly longer than the underlying data (special cases)
  // in percent: i.e. x % == (x / 100)

  DISPLAY_SENSITIVE_DATA_WARNING = 1; // 0 means skip or use --skip-sensitive-data-warning

  SEVEN_ZIP_UNCOMPRESSED = 0;
  SEVEN_ZIP_LZMA1_COMPRESSED = 1;
  SEVEN_ZIP_LZMA2_COMPRESSED = 2;
  SEVEN_ZIP_PPMD_COMPRESSED = 3;
  SEVEN_ZIP_BZIP2_COMPRESSED = 6;
  SEVEN_ZIP_DEFLATE_COMPRESSED = 7;

  SEVEN_ZIP_BCJ_PREPROCESSED = 1;
  SEVEN_ZIP_BCJ2_PREPROCESSED = 2;
  SEVEN_ZIP_PPC_PREPROCESSED = 3;
  SEVEN_ZIP_IA64_PREPROCESSED = 4;
  SEVEN_ZIP_ARM_PREPROCESSED = 5;
  SEVEN_ZIP_ARMT_PREPROCESSED = 6;
  SEVEN_ZIP_SPARC_PREPROCESSED = 7;

  PASSWORD_RECOVERY_TOOL_NAME = 'hashcat';
  PASSWORD_RECOVERY_TOOL_DATA_LIMIT = 16 * 1024 * 1024; // hexadecimal output value. This value should always be >= 64
  PASSWORD_RECOVERY_TOOL_SUPPORT_PADDING_ATTACK = 0; // does the cracker support the AES-CBC padding attack (0 means no, 1 means yes)
  PASSWORD_RECOVERY_TOOL_SUPPORTED_DECOMPRESSORS: set of byte = [SEVEN_ZIP_LZMA1_COMPRESSED, SEVEN_ZIP_LZMA2_COMPRESSED]; // within this list we only need values ranging from 1 to 7
  // i.e. SEVEN_ZIP_LZMA1_COMPRESSED to SEVEN_ZIP_DEFLATE_COMPRESSED
  PASSWORD_RECOVERY_TOOL_SUPPORTED_PREPROCESSORS: set of byte = [0]; // BCJ2 can be "supported" by ignoring CRC

  // 7-zip specific stuff

  LZMA2_MIN_COMPRESSED_LEN = 16; // the raw data (decrypted) needs to be at least: 3 + 1 + 1, header (start + size) + at least one byte of data + end
  // therefore we need to have at least one AES BLOCK (128 bits = 16 bytes)

  // header

  SEVEN_ZIP_MAGIC = '7z' + AnsiChar($BC) + AnsiChar($AF) + AnsiChar($27) + AnsiChar($1C);
  SEVEN_ZIP_MAGIC_LEN = 6; // fixed length of $SEVEN_ZIP_MAGIC

  SEVEN_ZIP_END = AnsiChar($00);
  SEVEN_ZIP_HEADER = AnsiChar($01);
  SEVEN_ZIP_ARCHIVE_PROPERTIES = AnsiChar($02);
  SEVEN_ZIP_ADD_STREAMS_INFO = AnsiChar($03);
  SEVEN_ZIP_MAIN_STREAMS_INFO = AnsiChar($04);
  SEVEN_ZIP_FILES_INFO = AnsiChar($05);
  SEVEN_ZIP_PACK_INFO = AnsiChar($06);
  SEVEN_ZIP_UNPACK_INFO = AnsiChar($07);
  SEVEN_ZIP_SUBSTREAMS_INFO = AnsiChar($08);
  SEVEN_ZIP_SIZE = AnsiChar($09);
  SEVEN_ZIP_CRC = AnsiChar($0A);
  SEVEN_ZIP_FOLDER = AnsiChar($0B);
  SEVEN_ZIP_UNPACK_SIZE = AnsiChar($0C);
  SEVEN_ZIP_NUM_UNPACK_STREAM = AnsiChar($0D);
  SEVEN_ZIP_EMPTY_STREAM = AnsiChar($0E);
  SEVEN_ZIP_EMPTY_FILE = AnsiChar($0F);
  SEVEN_ZIP_ANTI_FILE = AnsiChar($10);
  SEVEN_ZIP_NAME = AnsiChar($11);
  SEVEN_ZIP_CREATION_TIME = AnsiChar($12);
  SEVEN_ZIP_ACCESS_TIME = AnsiChar($13);
  SEVEN_ZIP_MODIFICATION_TIME = AnsiChar($14);
  SEVEN_ZIP_WIN_ATTRIBUTE = AnsiChar($15);
  SEVEN_ZIP_ENCODED_HEADER = AnsiChar($17);
  SEVEN_ZIP_START_POS = AnsiChar($18);
  SEVEN_ZIP_DUMMY = AnsiChar($19);

  SEVEN_ZIP_MAX_PROPERTY_TYPE = 1073741824; // 2 ** 30 = 1073741824
  SEVEN_ZIP_NOT_EXTERNAL = AnsiChar($00);
  SEVEN_ZIP_EXTERNAL = AnsiChar($01);
  SEVEN_ZIP_ALL_DEFINED = AnsiChar($01);
  SEVEN_ZIP_FILE_NAME_END = AnsiChar($00) + AnsiChar($00);

  // codec

  SEVEN_ZIP_AES = AnsiChar($06) + AnsiChar($F1) + AnsiChar($07) + AnsiChar($01); // all the following codec values are from CPP/7zip/Archive/7z/7zHeader.h

  SEVEN_ZIP_LZMA1 = AnsiChar($03) + AnsiChar($01) + AnsiChar($01);
  SEVEN_ZIP_LZMA2 = AnsiChar($21);
  SEVEN_ZIP_PPMD = AnsiChar($03) + AnsiChar($04) + AnsiChar($01);
  SEVEN_ZIP_BCJ = AnsiChar($03) + AnsiChar($03) + AnsiChar($01) + AnsiChar($03);
  SEVEN_ZIP_BCJ2 = AnsiChar($03) + AnsiChar($03) + AnsiChar($01) + AnsiChar($1B);
  SEVEN_ZIP_PPC = AnsiChar($03) + AnsiChar($03) + AnsiChar($02) + AnsiChar($05);
  SEVEN_ZIP_ALPHA = AnsiChar($03) + AnsiChar($03) + AnsiChar($03) + AnsiChar($01);
  SEVEN_ZIP_IA64 = AnsiChar($03) + AnsiChar($03) + AnsiChar($04) + AnsiChar($01);
  SEVEN_ZIP_ARM = AnsiChar($03) + AnsiChar($03) + AnsiChar($05) + AnsiChar($01);
  SEVEN_ZIP_ARMT = AnsiChar($03) + AnsiChar($03) + AnsiChar($07) + AnsiChar($01);
  SEVEN_ZIP_SPARC = AnsiChar($03) + AnsiChar($03) + AnsiChar($08) + AnsiChar($05);
  SEVEN_ZIP_BZIP2 = AnsiChar($04) + AnsiChar($02) + AnsiChar($02);
  SEVEN_ZIP_DEFLATE = AnsiChar($04) + AnsiChar($01) + AnsiChar($08);

  // hash format

  SEVEN_ZIP_HASH_SIGNATURE = '$7z$';
  SEVEN_ZIP_DEFAULT_POWER = 19;
  SEVEN_ZIP_DEFAULT_IV = AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00) + AnsiChar($00);

  SEVEN_ZIP_TRUNCATED = 128; // (0x80 or 0b10000000)

type
  tdigest = record
    crc: cardinal;
    defined: boolean;
  end;

  tdigests = array of tdigest;

  tsignature = record
    major_version: integer;
    minor_version: integer;
    next_header_offset: uint64;
    next_header_size: uint64;
    position_after_header: cardinal;
  end;

  tfiles_with_sizes = array of record
    fh: tstream; // the file handle
    num: integer;
    name: string;
    size: cardinal;
    start: cardinal;
  end;

  tsubstreams_info = record
    unpack_stream_numbers: array of integer;
    unpack_sizes: array of integer;
    number_digests: integer;
    digests: tdigests;
  end;

  tpack_info = record
    number_pack_streams: integer;
    pack_pos: integer;
    pack_sizes: array of integer;
  end;

  tcoder = record
    codec_id: ansistring;
    number_input_streams: integer;
    number_output_streams: integer;
    attributes: ansistring;
  end;

  tfolder = record
    number_coders: integer;
    coders: array of tcoder;
    bindpairs: array [0 .. 1] of integer;
    index_main_stream: integer;
    sum_input_streams: integer;
    sum_output_streams: integer;
    sum_packed_streams: integer;
  end;

  tunpack_info = record
    number_folders: integer;
    folders: array of tfolder;
    datastream_indices: array of integer;
    digests: tdigests;
    unpack_sizes: array of integer;
    main_unpack_size_index: array of integer;
    coder_unpack_sizes: array of integer;
  end;

  tstreams_info = record
    pack_info: tpack_info;
    unpack_info: tunpack_info;
    substreams_info: tsubstreams_info;
  end;

  tfile = record
    name_utf16: ansistring;
    attribute_defined: boolean;
    attribute: uint32;
    is_empty_stream: boolean;
    start_position: uint64;
    creation_time: uint64;
    access_time: uint64;
    modification_time: uint64;
    size: integer;
    has_stream: boolean;
    is_dir: boolean;
    crc_defined: boolean;
    crc: cardinal;
  end;

  tfiles_info = record
    number_files: integer;
    files: array of tfile;
  end;

  theader = record
    additional_streams_info: tstreams_info;
    streams_info: tstreams_info;
    files_info: tfiles_info;
    type_: ansistring;
  end;

  tarchive = record
    signature_header: tsignature;
    parsed_header: theader;
  end;

  TArrayStrings = array of string;
  TArrayBool = array of boolean;
  TArrayUInt64 = array of uint64;

var
  memory_buffer_read_offset: cardinal = 0;
  display_sensitive_warning: integer = DISPLAY_SENSITIVE_DATA_WARNING;
  first_file, was_splitted: integer;
  file_parameters: TArrayStrings;
  file_list: TArrayStrings;
  res, i: integer;
  hash_buf: string;

  //
  // Helper functions
  //

function getName(id: integer): ansistring;
begin
  case id of
    1:
      Result := 'LZMA1';
    2:
      Result := 'LZMA2';
    3:
      Result := 'PPMD';
    6:
      Result := 'BZIP2';
    7:
      Result := 'DEFLATE';
    1 shl 4:
      Result := 'BCJ';
    2 shl 4:
      Result := 'BCJ2';
    3 shl 4:
      Result := 'PPC';
    4 shl 4:
      Result := 'IA64';
    5 shl 4:
      Result := 'ARM';
    6 shl 4:
      Result := 'ARMT';
    7 shl 4:
      Result := 'SPARC';
  end;
end;

function unpack_hex(val: ansistring): ansistring;
var
  i: integer;
  s: ansistring;
begin

  SetLength(Result, Length(val) * 2);

  for i := 0 to Length(val) - 1 do
  begin

    s := inttohex(ord(val[i + 1]), 2);

    Result[i * 2 + 1] := s[1];
    Result[i * 2 + 2] := s[2];
  end;

  Result := lowercase(Result);

end;

procedure usage();
begin
  WriteLn('Usage: ' + ExtractFileName(ParamStr(0)) + ' <7-Zip file>...');
end;

function my_read(input: tstream; Length: integer): ansistring; overload;
var
  output_buffer: ansistring;
begin
  if input is TFileStream then
  begin
    SetLength(output_buffer, Length);
    input.Read(Pointer(output_buffer)^, Length);
    Result := output_buffer;
  end
  else
  begin // is TMemoryStream
    input.Seek(memory_buffer_read_offset, soBeginning);
    SetLength(output_buffer, Length);
    input.Read(Pointer(output_buffer)^, Length);
    memory_buffer_read_offset := memory_buffer_read_offset + length;
    Result := output_buffer;
  end
end;

function my_read(input: tstream; Length: integer; var res: uint): ansistring; overload;
begin
  if (input.Read(Pointer(res)^, sizeof(res)) <> sizeof(res)) then
    Result := ''
  else
    Result := '0';
end;

function my_read(input: tstream; Length: integer; var res: uint64): ansistring; overload;
begin
  res := 0;
  if (input.Read(Pointer(res)^, sizeof(res)) <> sizeof(res)) then
    Result := ''
  else
    Result := '0';
end;

function my_tell(input: tstream): cardinal; overload;
begin
  Result := input.Position;
end;

function my_seek(input: tstream; offset, whence: integer): integer; overload;
begin
  Result := input.Seek(offset, whence);
end;

function get_uint32(fp: tstream): uint32;
var
  bytes: ansistring;
begin
  bytes := my_read(fp, 4);

  if (Length(bytes) <> 4) then
  begin
    Result := 0;
    exit;
  end;

  Move(bytes, Result, 4);
  // $num := unpack ("L", $bytes);

  // return $num;}
end;

function get_uint64(fp: tstream): uint64;
var
  bytes: ansistring;
  uint1, uint2: uint;
begin
  bytes := my_read(fp, 8);

  if (Length(bytes) <> 8) then
  begin
    Result := 0;
    exit;
  end;

  Move(bytes[1], uint1, 4);
  Move(bytes[5], uint2, 4);

  Result := uint2 shl 32 or uint1;
end;

function read_number(fp: tstream): integer; overload;
var
  bytes: ansistring;
  b, value, mask, high, next: integer;
  i: integer;
begin
  bytes := my_read(fp, 1);
  b := ord(bytes[1]);

  if ((b and $80) = 0) then
  begin
    Result := b;
    exit;
  end;

  bytes := my_read(fp, 1);
  value := ord(bytes[1]);

  // for ($i = 1; $i < 8; $i++)
  for i := 1 to 7 do
  begin
    mask := $80 shr i;

    if ((b and mask) = 0) then
    begin
      high := b and (mask - 1);
      value := value or (high shl (i * 8));
      Result := value;
      exit;
    end;

    bytes := my_read(fp, 1);
    next := ord(bytes[1]);

    value := value or (next shl (i * 8));
  end;

  Result := value;
end;

function num_to_id(num: integer): ansistring;
var
  value: integer;
begin
  // special case:

  if (num = 0) then
  begin
    Result := #0;
    exit;
  end;

  // normal case:

  Result := '';

  while (num > 0) do
  begin
    value := num and $FF;

    Result := chr(value) + Result;

    num := num shr 8;
  end
end;

function read_id(fp: tstream): ansistring; overload;
begin
  Result := num_to_id(read_number(fp));
end;

procedure get_boolean_vector(fp: tstream; number_items: integer; var booleans: TArrayBool);
var
  i: integer;
  v, mask: integer;
  byte: ansistring;
begin
  // get the values

  SetLength(booleans, number_items);
  for i := 0 to number_items - 1 do
  begin
    if (mask = 0) then
    begin
      byte := my_read(fp, 1);

      v := ord(byte[1]);
      mask := $80;
    end;

    booleans[i] := (v and mask) <> 0;

    mask := mask shr 1;
  end
end;

procedure get_boolean_vector_check_all(fp: tstream; number_items: integer; var booleans: TArrayBool);
var
  all_defined: ansistring;
  i: integer;
begin
  // check first byte to see if all are defined

  all_defined := my_read(fp, 1);

  if (all_defined = SEVEN_ZIP_ALL_DEFINED) then
  begin
    SetLength(booleans, number_items);
    for i := 0 to Length(booleans) - 1 do
      booleans[i] := true;
  end
  else
  begin
    get_boolean_vector(fp, number_items, booleans);
  end
end;

function is_supported_seven_zip_file(fp: tstream): boolean;
var
  magic_len: integer;
  signature: ansistring;
begin
  magic_len := Length(SEVEN_ZIP_MAGIC);
  signature := my_read(fp, magic_len);
  Result := signature = SEVEN_ZIP_MAGIC;
end;

procedure get_decoder_properties(attributes: ansistring; var salt_len, iv_len: integer; var iv_buf, salt_buf: ansistring; var number_cycles_power: integer);
var
  offset: integer;
  first_byte, second_byte, iv_max_length: integer;
begin
  // set some default values

  salt_len := 0;
  salt_buf := '';
  iv_len := Length(SEVEN_ZIP_DEFAULT_IV);
  iv_buf := SEVEN_ZIP_DEFAULT_IV;
  number_cycles_power := SEVEN_ZIP_DEFAULT_POWER;

  // the most important information is encoded in first and second byte
  // i.e. the salt/iv length, number cycle power

  offset := 0;
  first_byte := 0;
  if (Length(attributes) >= 1) then
    first_byte := ord(attributes[1]);

  inc(offset);

  number_cycles_power := first_byte and $3F;

  if ((first_byte and $C0) = 0) then
  begin
    exit;
  end;

  salt_len := (first_byte shr 7) and 1;
  iv_len := (first_byte shr 6) and 1;

  // combine this info with the second byte
  second_byte := 0;
  if (Length(attributes) >= 2) then
    second_byte := ord(attributes[2]);

  inc(offset);

  salt_len := salt_len + (second_byte shr 4);
  iv_len := iv_len + (second_byte and $0F);

  salt_buf := copy(attributes, offset + 1, salt_len);

  inc(offset, salt_len);

  iv_buf := copy(attributes, offset + 1, iv_len);

  // pad the iv with zeros

  iv_max_length := 16;

  iv_buf := iv_buf + #0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0; // #0 x iv_max_length
  iv_buf := copy(iv_buf, 1, iv_max_length);
end;

function get_digest(index: integer; unpack_info: tunpack_info; substreams_info: tsubstreams_info; var res: integer): tdigest;
begin
  if (Length(unpack_info.digests) > 0) then
  begin
    Result := unpack_info.digests[index];
  end
  else if (Length(substreams_info.digests) > 0) then
  begin
    Result := substreams_info.digests[index];
  end;
end;

function has_encrypted_header(folder: tfolder): boolean;
begin
  // get first coder
  // get attributes of the first coder
  Result := (folder.coders[0].codec_id = SEVEN_ZIP_AES);
end;

procedure lzma_properties_decode(attributes: ansistring; var lclppb: ansistring; var lc, lp, pb, dict_size: integer);
var
  data: array [1 .. 4] of integer;
  d: integer;
begin
  lclppb := copy(attributes, 1, 1);

  // data[0] is the lclppb value

  data[1] := ord(copy(attributes, 2, 1)[1]);
  data[2] := ord(copy(attributes, 3, 1)[1]);
  data[3] := ord(copy(attributes, 4, 1)[1]);
  data[4] := ord(copy(attributes, 5, 1)[1]);

  dict_size := data[1] or data[2] shl 8 or data[3] shl 16 or data[4] shl 24;

  if (dict_size < LZMA_DICT_SIZE_MIN) then
  begin
    dict_size := LZMA_DICT_SIZE_MIN;
  end;

  d := ord(lclppb[1]);

  lc := d mod 9;
  d := d div 9;
  pb := d div 5;
  lp := d mod 5;
end;

function lzma_alone_header_field_encode(num, length_: integer): ansistring;
var
  length_doubled, i: integer;
  big_endian_val, value: ansistring;
begin
  length_doubled := length_ * 2;
  big_endian_val := inttohex(num, length_doubled);
  value := '';
  for i := 0 to length_ - 1 do
    value := value + char(StrToInt('$' + copy(big_endian_val, (i * 2) + 1, 2)));

  // pack ("H*", sprintf ("%0[length_doubled]x", num));

  // what follows is just some easy way to convert endianess (there might be better ways of course)

  Result := '';

  for i := length_ downto 1 do
  begin
    Result := Result + copy(value, i, 1);
  end;
end;

function read_seven_zip_signature_header(fp: tstream): tsignature;
var
  signature: tsignature;
  c: ansistring;
begin
  // ArchiveVersion
  c := my_read(fp, 1);

  signature.major_version := ord(c[1]);

  c := my_read(fp, 1);

  signature.minor_version := ord(c[1]);

  // StartHeaderCRC
  my_read(fp, 4); // skip start header CRC

  // StartHeader
  signature.next_header_offset := get_uint64(fp);
  signature.next_header_size := get_uint64(fp);

  my_read(fp, 4); // next header CRC

  signature.position_after_header := my_tell(fp);

  Result := signature;
end;

procedure skip_seven_zip_data(fp: tstream); overload;
var
  len: ansistring;
begin
  // determine the length to skip

  len := my_read(fp, 1);

  // do skip len bytes
  my_read(fp, ord(len[1]));
end;

function wait_for_seven_zip_id(fp: tstream; id: ansistring): boolean;
var
  new_id: ansistring;
begin
  while (true) do
  begin
    new_id := read_id(fp);

    if (new_id = id) then
    begin
      Result := true;
      exit;
    end
    else if (new_id = SEVEN_ZIP_END) then
    begin
      Result := False;
      exit;
    end;

    skip_seven_zip_data(fp);
  end;

  Result := False;
end;

procedure read_seven_zip_digests(fp: tstream; number_items: integer; var digests: tdigests);
var
  i, j: integer;
  digests_defined: TArrayBool;
  val: ansistring;
  crc: cardinal;
begin
  SetLength(digests, number_items);

  // init

  for i := 0 to number_items - 1 do
  begin
    digests[i].crc := 0;
    digests[i].defined := False;
  end;

  // get number of items

  get_boolean_vector_check_all(fp, number_items, digests_defined);

  // for each number of item, get a digest

  for i := 0 to number_items - 1 do
  begin
    crc := 0;

    for j := 0 to 3 do
    begin
      val := my_read(fp, 1);

      crc := crc or (ord(val[1]) shl (8 * j));
    end;

    digests[i].crc := crc;
    digests[i].defined := digests_defined[i];
  end
end;

function read_seven_zip_pack_info(fp: tstream; var res: integer): tpack_info; overload;
var
  pack_pos, number_pack_streams: integer;
  id: ansistring;
  digests: tdigests;
  i: integer;
begin
  // PackPos

  pack_pos := read_number(fp);

  // NumPackStreams

  number_pack_streams := read_number(fp);

  // must be "size" id

  if (not wait_for_seven_zip_id(fp, SEVEN_ZIP_SIZE)) then
  begin
    res := UNDEF;
    exit;
  end;

  SetLength(Result.pack_sizes, number_pack_streams);

  for i := 0 to number_pack_streams - 1 do
  begin
    Result.pack_sizes[i] := read_number(fp);
  end;

  Result.number_pack_streams := number_pack_streams;
  Result.pack_pos := pack_pos;

  // read remaining data

  while (true) do
  begin
    id := read_id(fp);

    if (id = SEVEN_ZIP_END) then
    begin
      exit;
    end
    else if (id = SEVEN_ZIP_CRC) then
    begin
      read_seven_zip_digests(fp, number_pack_streams, digests);

      // we do not need those digests, ignore them
      // (but we need to read them from the stream)

      continue;
    end;

    skip_seven_zip_data(fp);
  end

  // something went wrong
end;

function read_seven_zip_folders(fp: tstream; var res: integer): tfolder;
var
  i, property_size, number_bindpairs, index_input, index_output: integer;
  main_byte: ansistring;
  codec_id_size: integer;
  input_stream_used, output_stream_used: array of integer;
begin
  Result.index_main_stream := 0;
  Result.sum_input_streams := 0;
  Result.sum_output_streams := 0;
  Result.sum_packed_streams := 1;

  // NumCoders

  Result.number_coders := read_number(fp);

  // loop
  SetLength(Result.coders, Result.number_coders);
  for i := 0 to Result.number_coders - 1 do
  begin
    main_byte := my_read(fp, 1);

    if (ord(main_byte[1]) and $C0 <> 0) then // ???????????????????
    begin
      res := UNDEF;
      exit;
    end;

    codec_id_size := ord(main_byte[1]) and $F;

    if (codec_id_size > 8) then
    begin
      res := UNDEF;
      exit;
    end;

    // the codec id (very important info for us):
    // codec_id: 06F10701 -> AES-256 + SHA-256
    // codec_id: 030101   -> lzma  (we need to decompress - k_LZMA)
    // codec_id: 21       -> lzma2 (we need to decompress - k_LZMA2)

    Result.coders[i].codec_id := my_read(fp, codec_id_size);

    // NumInStreams

    Result.coders[i].number_input_streams := 1;

    // NumOutStreams

    Result.coders[i].number_output_streams := 1;

    if (ord(main_byte[1]) and $10 <> 0) then
    begin
      Result.coders[i].number_input_streams := read_number(fp);
      Result.coders[i].number_output_streams := read_number(fp);
    end;

    Result.sum_input_streams := Result.sum_input_streams + Result.coders[i].number_input_streams;
    Result.sum_output_streams := Result.sum_output_streams + Result.coders[i].number_output_streams;

    // attributes

    if (ord(main_byte[1]) and $020 <> 0) then
    begin
      property_size := read_number(fp);

      Result.coders[i].attributes := my_read(fp, property_size);
    end;
  end;

  if ((Result.sum_input_streams <> 1) or (Result.sum_output_streams <> 1)) then
  begin
    // InStreamUsed / OutStreamUsed

    SetLength(input_stream_used, Result.sum_input_streams);
    SetLength(output_stream_used, Result.sum_output_streams);

    // BindPairs

    number_bindpairs := Result.sum_output_streams - 1;

    for i := 0 to number_bindpairs - 1 do
    begin
      // input

      index_input := read_number(fp);

      if (input_stream_used[index_input] = 1) then
      begin
        res := UNDEF;
        exit;
      end;

      input_stream_used[index_input] := 1;

      // output

      index_output := read_number(fp);

      if (output_stream_used[index_output] = 1) then
      begin
        res := UNDEF;
        exit;
      end;

      output_stream_used[index_output] := 1;

      // new_bindpair = (index_input, index_output);
      Result.bindpairs[0] := index_input;
      Result.bindpairs[1] := index_output;
      // push (@bindpairs, \@new_bindpair);
    end;

    // PackedStreams

    Result.sum_packed_streams := Result.sum_input_streams - number_bindpairs;

    if (Result.sum_packed_streams <> 1) then
    begin
      for i := 0 to Result.sum_packed_streams - 1 do
      begin
        // we can ignore this

        read_number(fp); // $index = read_number (fp);
      end
    end;

    // determine the main stream

    Result.index_main_stream := -1;

    for i := 0 to Result.sum_output_streams - 1 do
    begin
      if (output_stream_used[i] = 0) then
      begin
        Result.index_main_stream := i;
        break;
      end
    end;

    if (Result.index_main_stream = -1) then
    begin
      res := UNDEF;
      exit;
    end
  end;

  // $folder = begin
  // "number_coders" => $number_coders,
  // "coders" => \@coders,
  // "bindpairs" => \@bindpairs,
  // "index_main_stream"  => $index_main_stream,
  // "sum_input_streams"  => $sum_input_streams,
  // "sum_output_streams" => $sum_output_streams,
  // "sum_packed_streams" => $sum_packed_streams,
  // end;
end;

function read_seven_zip_unpack_info(fp: tstream; var res: integer): tunpack_info; overload;
var
  external_, id: ansistring;
  sum_coders_output_streams: integer;
  sum_folders, i: integer;
  new_digests: tdigests;
begin
  Result.number_folders := 0;

  // check until we see the "folder" id

  if (not wait_for_seven_zip_id(fp, SEVEN_ZIP_FOLDER)) then
  begin
    res := UNDEF;
    exit;
  end;

  // NumFolders

  Result.number_folders := read_number(fp);

  // External

  external_ := my_read(fp, 1);

  // loop

  sum_coders_output_streams := 0;
  sum_folders := 0;

  for i := 0 to Result.number_folders - 1 do
  begin
    if (external_ = SEVEN_ZIP_NOT_EXTERNAL) then
    begin
      SetLength(Result.folders, Length(Result.folders) + 1);
      Result.folders[i] := read_seven_zip_folders(fp, res);

      SetLength(Result.main_unpack_size_index, Length(Result.main_unpack_size_index) + 1);
      Result.main_unpack_size_index[i] := Result.folders[i].index_main_stream;
      SetLength(Result.coder_unpack_sizes, Length(Result.coder_unpack_sizes) + 1);
      Result.coder_unpack_sizes[i] := sum_coders_output_streams;

      sum_coders_output_streams := sum_coders_output_streams + Result.folders[i].sum_output_streams;
      sum_folders := sum_folders + 1;
    end
    else if (external_ = SEVEN_ZIP_EXTERNAL) then
    begin
      SetLength(Result.datastream_indices, Length(Result.datastream_indices) + 1);
      Result.datastream_indices[i] := read_number(fp);
    end
    else
    begin
      res := UNDEF;
      exit;
    end
  end;

  if (not wait_for_seven_zip_id(fp, SEVEN_ZIP_UNPACK_SIZE)) then
  begin
    res := UNDEF;
    exit;
  end;

  SetLength(Result.unpack_sizes, sum_coders_output_streams);
  for i := 0 to sum_coders_output_streams - 1 do
  begin
    Result.unpack_sizes[i] := read_number(fp);
  end;

  // read remaining data

  while (true) do
  begin
    id := read_id(fp);

    if (id = SEVEN_ZIP_END) then
    begin
      exit;
    end
    else if (id = SEVEN_ZIP_CRC) then
    begin
      read_seven_zip_digests(fp, sum_folders, new_digests);

      SetLength(Result.digests, sum_folders);
      for i := 0 to sum_folders - 1 do
      begin
        Result.digests[i].defined := new_digests[i].defined;
        Result.digests[i].crc := new_digests[i].crc;
      end;

      continue;
    end;

    skip_seven_zip_data(fp);
  end;

  // something went wrong
end;

function get_folder_unpack_size(unpack_info: tunpack_info; folder_index: integer): integer;
var
  index: integer;
begin
  index := unpack_info.coder_unpack_sizes[folder_index] + unpack_info.main_unpack_size_index[folder_index];

  Result := unpack_info.unpack_sizes[index];
end;

function has_valid_folder_crc(digests: tdigests; index: integer): boolean;
begin
  if (Length(digests) <= index) then
  begin
    Result := False;
    exit;
  end;

  // $digest = @$digests[$index];

  if (not digests[index].defined) then
  begin
    Result := False;
    exit;
  end;

  if (digests[index].crc = 0) then
  begin
    Result := False;
    exit;
  end;

  Result := true;
end;

function read_seven_zip_substreams_info(fp: tstream; unpack_info: tunpack_info; var res: integer): tsubstreams_info; overload;
var
  val, id: ansistring;
  i, j, h, k, k2: integer;
  sum_unpack_sizes, folder_unpack_size: integer;
  number_substreams: integer;
  digest: integer;
  is_digest_defined: TArrayBool;
  defined: boolean;
begin
  // $folders = $unpack_info.folders;
  // $folders_digests = $unpack_info.digests;

  SetLength(Result.unpack_stream_numbers, unpack_info.number_folders);
  for i := 0 to Length(Result.unpack_stream_numbers) - 1 do
    Result.unpack_stream_numbers[i] := 1;

  // Result.unpack_sizes;
  // Result.digests;

  // get the numbers of unpack streams

  while (true) do
  begin
    id := read_id(fp);

    if (id = SEVEN_ZIP_NUM_UNPACK_STREAM) then
    begin
      for i := 0 to unpack_info.number_folders - 1 do
      begin
        Result.unpack_stream_numbers[i] := read_number(fp);
      end;

      continue;
    end
    else if (id = SEVEN_ZIP_CRC) then
    begin
      break;
    end
    else if (id = SEVEN_ZIP_SIZE) then
    begin
      break;
    end
    else if (id = SEVEN_ZIP_END) then
    begin
      break;
    end;

    skip_seven_zip_data(fp);
  end;

  if (id = SEVEN_ZIP_SIZE) then
  begin
    for i := 0 to unpack_info.number_folders - 1 do
    begin
      if (Result.unpack_stream_numbers[i] = 0) then
      begin
        continue;
      end;

      sum_unpack_sizes := 0;

      for j := 1 to Result.unpack_stream_numbers[i] - 1 do
      begin
        SetLength(Result.unpack_sizes, Length(Result.unpack_sizes)+1);
        if Length(Result.unpack_sizes) > 0 then begin
          Result.unpack_sizes[Length(Result.unpack_sizes) - 1] := read_number(fp);
        // push (@unpack_sizes, $size);

          sum_unpack_sizes := sum_unpack_sizes + Result.unpack_sizes[Length(Result.unpack_sizes) - 1];
        end;
      end;

      // add the folder unpack size itself
      folder_unpack_size := get_folder_unpack_size(unpack_info, i);

      if (folder_unpack_size < sum_unpack_sizes) then
      begin
        res := UNDEF;
        exit;
        // return undef;
      end;

      SetLength(Result.unpack_sizes, Length(Result.unpack_sizes)+1);
      if Length(Result.unpack_sizes) > 0 then
        Result.unpack_sizes[Length(Result.unpack_sizes) - 1] := folder_unpack_size - sum_unpack_sizes;
      // push (@unpack_sizes, $size);
    end;

    id := read_id(fp);
  end
  else
  begin
    for i := 0 to unpack_info.number_folders - 1 do
    begin
      number_substreams := Result.unpack_stream_numbers[i];

      if (number_substreams > 1) then
      begin
        res := UNDEF;
        exit;
      end;

      if (number_substreams = 1) then
      begin
        SetLength(Result.unpack_sizes, Length(Result.unpack_sizes) + 1);
        Result.unpack_sizes[Length(Result.unpack_sizes) - 1] := get_folder_unpack_size(unpack_info, i);
      end
    end
  end;

  Result.number_digests := 0;

  for i := 0 to unpack_info.number_folders - 1 do
  begin
    number_substreams := Result.unpack_stream_numbers[i];

    if ((number_substreams <> 1) or (has_valid_folder_crc(unpack_info.digests, i) = False)) then
    begin
      Result.number_digests := Result.number_digests + number_substreams;
    end
  end;

  while (true) do
  begin
    if (id = SEVEN_ZIP_END) then
    begin
      break;
    end
    else if (id = SEVEN_ZIP_CRC) then
    begin
      get_boolean_vector_check_all(fp, Result.number_digests, is_digest_defined);

      k := 0;
      k2 := 0;

      for i := 0 to unpack_info.number_folders - 1 do
      begin
        number_substreams := Result.unpack_stream_numbers[i];

        if ((number_substreams = 1) and (has_valid_folder_crc(unpack_info.digests, i))) then
        begin
          SetLength(Result.digests, Length(Result.digests) + 1);
          Result.digests[k].defined := true;
          Result.digests[k].crc := unpack_info.digests[i].crc;
          inc(k);
        end
        else
        begin
          for j := 0 to number_substreams - 1 do
          begin
            defined := is_digest_defined[k2];

            // increase k2

            inc(k2);

            SetLength(Result.digests, Length(Result.digests) + 1);
            if (defined) then
            begin
              digest := 0;

              for h := 0 to 3 do
              begin
                val := my_read(fp, 1);
                digest := digest or (ord(val[1]) shl (8 * h));
              end;

              Result.digests[k].defined := true;
              Result.digests[k].crc := digest;
            end
            else
            begin
              Result.digests[k].defined := False;
              Result.digests[k].crc := 0;
            end;

            inc(k);
          end
        end
      end
    end
    else
    begin
      skip_seven_zip_data(fp);
    end;

    id := read_id(fp);
  end;

  if (Length(Result.digests) <> Length(Result.unpack_sizes)) then
  begin
    k := 0;

    for i := 0 to unpack_info.number_folders - 1 do
    begin
      number_substreams := Result.unpack_stream_numbers[i];

      if ((number_substreams = 1) and (has_valid_folder_crc(unpack_info.digests, i))) then
      begin
        SetLength(Result.digests, Length(Result.digests) + 1);
        Result.digests[k].defined := true;
        Result.digests[k].crc := unpack_info.digests[i].crc;

        inc(k);
      end
      else
      begin
        for j := 0 to number_substreams - 1 do
        begin
          SetLength(Result.digests, Length(Result.digests) + 1);
          Result.digests[k].defined := False;
          Result.digests[k].crc := 0;

          inc(k);
        end
      end
    end
  end

  // $substreams_info = begin
  // "unpack_stream_numbers" => \@number_unpack_streams,
  // "unpack_sizes" => \@unpack_sizes,
  // "number_digests" => $number_digests,
  // "digests" => \@digests
  // end;
  //
  // return $substreams_info;
end;

function read_seven_zip_streams_info(fp: tstream; var res: integer): tstreams_info; overload;
var
  id: ansistring;
  streams_info: tstreams_info;
  substreams_info: tsubstreams_info;
  pack_info: tpack_info;
  unpack_info: tunpack_info;

  number_unpack_streams: array of integer;
  unpack_sizes: array of integer;
  number_digests, i: integer;
  // digests : ansistring;
  // folders : integer;
  number_folders: integer;
  folder_unpack_size: integer;
begin
  // get the type of streams info (id)

  id := read_id(fp);

  if (id = SEVEN_ZIP_PACK_INFO) then
  begin
    pack_info := read_seven_zip_pack_info(fp, res);

    if (res = UNDEF) then
    begin
      exit;
      // return undef unless (defined ($pack_info));
    end;

    id := read_id(fp);
  end;

  if (id = SEVEN_ZIP_UNPACK_INFO) then
  begin
    unpack_info := read_seven_zip_unpack_info(fp, res);

    if (res = UNDEF) then
    begin
      exit;
      // return undef unless (defined ($unpack_info));
    end;

    id := read_id(fp);
  end;

  if (id = SEVEN_ZIP_SUBSTREAMS_INFO) then
  begin
    substreams_info := read_seven_zip_substreams_info(fp, unpack_info, res);

    if (res = UNDEF) then
    begin
      exit;
      // return undef unless (defined ($substreams_info));
    end;

    id := read_id(fp);
  end
  else
  begin
    if (res <> UNDEF) then
    begin
      // folders := unpack_info.folders;

      number_folders := unpack_info.number_folders;
      SetLength(number_unpack_streams, number_folders);
      for i := 0 to number_folders - 1 do
      begin
        number_unpack_streams[i] := 1;

        folder_unpack_size := get_folder_unpack_size(unpack_info, i);
        SetLength(unpack_sizes, Length(unpack_sizes) + 1);
        unpack_sizes[Length(unpack_sizes) - 1] := folder_unpack_size;
      end
    end;

    SetLength(number_unpack_streams, Length(substreams_info.unpack_stream_numbers));
    Move(substreams_info.unpack_stream_numbers, number_unpack_streams, Length(number_unpack_streams));

    SetLength(unpack_sizes, Length(substreams_info.unpack_sizes));
    Move(substreams_info.unpack_sizes, unpack_sizes, Length(unpack_sizes));

    substreams_info.number_digests := number_digests;
    // substreams_info.digests := digests;
  end;

  streams_info.pack_info := pack_info;
  streams_info.unpack_info := unpack_info;
  streams_info.substreams_info := substreams_info;

  Result := streams_info;
end;

function read_seven_zip_archive_properties(fp: tstream): boolean; overload;
var
  id: ansistring;
begin
  // also the 7-Zip source code just skip data from the archive property entry

  while (true) do
  begin
    id := read_id(fp);

    if (id = SEVEN_ZIP_END) then
    begin
      Result := true;
      exit;
    end;

    skip_seven_zip_data(fp);
  end;

  // something went wrong

  Result := False;
end;

procedure get_uint64_defined_vector(fp: tstream; number_items: integer; var values: TArrayUInt64);
var
  defines: TArrayBool;
  defined: boolean;
  external_: ansistring;
  i: integer;
  value: uint64;
begin
  // first check if the values are defined

  get_boolean_vector_check_all(fp, number_items, defines);

  external_ := my_read(fp, 1);

  if (external_ = SEVEN_ZIP_EXTERNAL) then
  begin
    // ignored for now
  end;

  SetLength(values, number_items);
  for i := 0 to number_items - 1 do
  begin
    defined := defines[i];

    value := 0;

    if (defined) then
    begin
      value := get_uint64(fp);
    end;

    values[i] := value;
  end
end;

function read_seven_zip_files_info(fp: tstream; streams_info: tstreams_info; var res: integer): tfiles_info; overload;
var
  files_info: tfiles_info;
  number_empty_streams, i, property_type_val, size, files_size, number_booleans, number_anti_items: integer;
  property_type, name_part, name, bytes, compare_bytes, external_, id: ansistring;
  empty_files, anti_files, empty_streams, booleans: TArrayBool;
  attributes: uint32;
  start_positions, creation_times, access_times, modification_times: TArrayUInt64;

  index_sizes, index_empty_files: integer;
  is_anti, has_stream, is_crc_defined, is_known_type, is_dir: boolean;
  crc_item: tdigest;

  unpack_info: tunpack_info;
  substreams_info: tsubstreams_info;

begin
  // NumFiles
  Result.number_files := read_number(fp);

  // init file

  SetLength(Result.files, Result.number_files);
  for i := 0 to Result.number_files - 1 do
  begin
    Result.files[i].name_utf16 := '';
    Result.files[i].attribute_defined := False;
    Result.files[i].attribute := 0;
    Result.files[i].is_empty_stream := False;
    Result.files[i].start_position := 0;
    Result.files[i].creation_time := 0;
    Result.files[i].access_time := 0;
    Result.files[i].modification_time := 0;
    Result.files[i].size := 0;
    Result.files[i].has_stream := False;
    Result.files[i].is_dir := False;
    Result.files[i].crc_defined := False;
    Result.files[i].crc := 0;
  end;

  number_empty_streams := 0;

  SetLength(empty_streams, Result.number_files);
  SetLength(empty_files, Result.number_files);
  SetLength(anti_files, Result.number_files);
  for i := 0 to Length(empty_streams) - 1 do
  begin
    empty_streams[i] := False;
    empty_files[i] := False;
    anti_files[i] := False;
  end;

  // loop over all properties

  while (true) do
  begin
    property_type_val := read_number(fp);

    property_type := num_to_id(property_type_val);

    if (property_type = SEVEN_ZIP_END) then
    begin
      break;
    end;

    // Size

    size := read_number(fp);

    // check and act according to the type of property found

    is_known_type := true;

    if (property_type_val > SEVEN_ZIP_MAX_PROPERTY_TYPE) then
    begin
      // ignore (isKnownType false in 7-Zip source code)

      my_read(fp, size);
    end
    else
    begin
      if (property_type = SEVEN_ZIP_NAME) then
      begin
        external_ := my_read(fp, 1);

        if (external_ = SEVEN_ZIP_EXTERNAL) then
        begin
          res := UNDEF;
          exit;
          // return undef;
        end;

        files_size := Length(Result.files);

        for i := 0 to files_size - 1 do
        begin
          name := '';

          while (true) do
          begin
            name_part := my_read(fp, 2);

            if (name_part = SEVEN_ZIP_FILE_NAME_END) then
            begin
              break;
            end
            else
            begin
              name := name + name_part;
            end
          end;

          Result.files[i].name_utf16 := name;
        end
      end
      else if (property_type = SEVEN_ZIP_WIN_ATTRIBUTE) then
      begin
        files_size := Length(Result.files);

        get_boolean_vector_check_all(fp, Result.number_files, booleans);

        external_ := my_read(fp, 1);

        if (external_ = SEVEN_ZIP_EXTERNAL) then
        begin
          res := UNDEF;
          exit;
          // return undef;
        end;

        for i := 0 to Result.number_files - 1 do
        begin
          Result.files[i].attribute_defined := booleans[i];

          if (booleans[i]) then
          begin
            attributes := get_uint32(fp);

            Result.files[i].attribute := attributes;
          end
        end
      end
      else if (property_type = SEVEN_ZIP_EMPTY_STREAM) then
      begin
        get_boolean_vector(fp, Result.number_files, empty_streams);

        number_empty_streams := 0;

        // loop over all boolean and set the files attribute + empty/anti stream vector

        number_booleans := Length(empty_streams);

        for i := 0 to number_booleans - 1 do
        begin
          Result.files[i].is_empty_stream := empty_streams[i];

          if (empty_streams[i]) then
          begin
            inc(number_empty_streams);
          end
        end;

        for i := 0 to number_empty_streams - 1 do
        begin
          empty_files[i] := False;
          anti_files[i] := False;
        end
      end
      else if (property_type = SEVEN_ZIP_EMPTY_FILE) then
      begin
        get_boolean_vector(fp, number_empty_streams, empty_files);
      end
      else if (property_type = SEVEN_ZIP_ANTI_FILE) then
      begin
        get_boolean_vector(fp, number_empty_streams, anti_files);
      end
      else if (property_type = SEVEN_ZIP_START_POS) then
      begin
        get_uint64_defined_vector(fp, Result.number_files, start_positions);

        for i := 0 to Length(start_positions) - 1 do
        begin
          Result.files[i].start_position := start_positions[i];
        end
      end
      else if (property_type = SEVEN_ZIP_CREATION_TIME) then
      begin
        get_uint64_defined_vector(fp, Result.number_files, creation_times);

        for i := 0 to Length(creation_times) - 1 do
        begin
          Result.files[i].creation_time := creation_times[i];
        end
      end
      else if (property_type = SEVEN_ZIP_ACCESS_TIME) then
      begin
        get_uint64_defined_vector(fp, Result.number_files, access_times);

        for i := 0 to Length(access_times) - 1 do
        begin
          Result.files[i].access_time := access_times[i];
        end
      end
      else if (property_type = SEVEN_ZIP_MODIFICATION_TIME) then
      begin
        get_uint64_defined_vector(fp, Result.number_files, modification_times);

        for i := 0 to Length(modification_times) - 1 do
        begin
          Result.files[i].modification_time := modification_times[i];
        end
      end
      else if (property_type = SEVEN_ZIP_DUMMY) then
      begin
        SetLength(compare_bytes, size);
        for i := 0 to Length(compare_bytes) - 1 do
          compare_bytes[i] := #0;

        bytes := my_read(fp, size);

        if (bytes <> compare_bytes) then
        begin
          res := UNDEF;
          exit;
        end
      end
      else
      begin
        // ignore (isKnownType also in 7-Zip source code)

        my_read(fp, size);
      end
    end
  end;

  // next id should be SEVEN_ZIP_END, but we (and 7-ZIP source code too) do not care

  id := read_id(fp);

  // check anti files

  number_anti_items := 0;

  for i := 0 to number_empty_streams - 1 do
  begin
    if (anti_files[i]) then
    begin
      inc(number_anti_items);
    end
  end;

  // set digests depending on empty/anti files

  index_sizes := 0;
  index_empty_files := 0;

  unpack_info := streams_info.unpack_info;
  substreams_info := streams_info.substreams_info;

  for i := 0 to Result.number_files - 1 do
  begin
    is_anti := False;
    has_stream := true;

    if (empty_streams[i]) then
    begin
      has_stream := False;
    end;

    Result.files[i].has_stream := has_stream;
    Result.files[i].crc := 0;

    if (has_stream) then
    begin
      is_anti := False;

      Result.files[i].is_dir := False;
      Result.files[i].size := unpack_info.unpack_sizes[index_sizes];

      Result.files[i].crc_defined := False;
      Result.files[i].crc := 0;

      is_crc_defined := has_valid_folder_crc(unpack_info.digests, index_sizes);

      if (is_crc_defined) then
      begin
        Result.files[i].crc_defined := true;
        crc_item := unpack_info.digests[index_sizes];

        Result.files[i].crc := crc_item.crc;
      end
      else
      begin
        // can we really do this too?

        is_crc_defined := has_valid_folder_crc(substreams_info.digests, index_sizes);

        if (is_crc_defined) then
        begin
          Result.files[i].crc_defined := true;

          crc_item := substreams_info.digests[index_sizes];

          Result.files[i].crc := crc_item.crc;
        end
      end;

      inc(index_sizes);
    end
    else
    begin
      is_dir := False;

      if (empty_files[index_empty_files] = False) then
      begin
        Result.files[i].is_dir := true;
      end
      else
      begin
        Result.files[i].is_dir := False;
      end;

      Result.files[i].size := 0;

      Result.files[i].crc_defined := False;
      Result.files[i].crc := 0;

      inc(index_empty_files);
    end
  end;
end;

function read_and_decode_seven_zip_packed_stream(fp: tstream; var res: integer): tstreams_info; overload;
begin
  Result := read_seven_zip_streams_info(fp, res);
end;

function read_seven_zip_header(fp: tstream; var res: integer): theader; overload;
var

  additional_streams_info: tstreams_info;
  streams_info: tstreams_info;
  files_info: tfiles_info;
  id: ansistring;
begin
  // get the type of header

  id := read_id(fp);

  if (id = SEVEN_ZIP_ARCHIVE_PROPERTIES) then
  begin
    // we just ignore the data here (but we need to read it from the stream!)

    if (not read_seven_zip_archive_properties(fp)) then
    begin
      res := UNDEF;
      exit;
      // return undef;
    end;

    id := read_id(fp);
  end;

  if (id = SEVEN_ZIP_ADD_STREAMS_INFO) then
  begin
    additional_streams_info := read_and_decode_seven_zip_packed_stream(fp, res);
    if res = UNDEF then
    begin
      exit;
      // return undef unless (defined ($additional_streams_info));
    end;

    // do we need to change the start position here ?

    id := read_id(fp);
  end;

  if (id = SEVEN_ZIP_MAIN_STREAMS_INFO) then
  begin
    streams_info := read_seven_zip_streams_info(fp, res);

    if res = UNDEF then
    begin
      exit;
      // return undef unless (defined ($streams_info));
    end;

    id := read_id(fp);
  end;

  if (id = SEVEN_ZIP_FILES_INFO) then
  begin
    files_info := read_seven_zip_files_info(fp, streams_info, res);

    if res = UNDEF then
    begin
      exit;
      // return undef unless (defined ($files_info));
    end;
  end;

  Result.additional_streams_info := additional_streams_info;
  Result.streams_info := streams_info;
  Result.files_info := files_info;
  Result.type_ := 'raw';
end;

function parse_seven_zip_header(fp: tstream; var res: integer): theader;
var
  id: ansistring;
  header: theader;
  streams_info: tstreams_info;
begin
  // $streams_info;

  // get the type of the header (id)

  id := read_id(fp);

  // check if either encoded/packed or encrypted: to get the details we need to check the method

  if (id <> SEVEN_ZIP_HEADER) then
  begin
    if (id <> SEVEN_ZIP_ENCODED_HEADER) then
    begin
      // when we reach this code section we probably found an invalid 7z file (just ignore it!)
      // writeln(ErrOutput, 'WARNING: only encoded headers are allowed if no raw header is present\n";
      res := UNDEF;
      exit;
      // return undef;
    end;

    streams_info := read_and_decode_seven_zip_packed_stream(fp, res);
    if res = UNDEF then
    begin
      exit;
      // return undef unless (defined ($streams_info));
    end;

    header.additional_streams_info.pack_info.number_pack_streams := UNDEF;
    header.streams_info := streams_info;
    header.files_info.number_files := UNDEF;
    header.type_ := 'encoded';

    // Note: now the 7-Zip code normally parses the header (which we got from the decode operation above)
    // but we do not really need to do this here. Skip
  end
  else
  begin
    header := read_seven_zip_header(fp, res);
  end;

  Result := header;
end;

function read_seven_zip_next_header(fp: tstream; header_size: uint64; header_offset: uint64; var res: integer): theader;
var
  header: theader;
begin
  // get the header of size header_size at relative position header_offset
  my_seek(fp, header_offset, 1);

  // read the header
  header := parse_seven_zip_header(fp, res);

  Result := header;
end;

function read_seven_zip_archive(fp: tstream; var res: integer): tarchive;
var
  archive: tarchive;
begin
  // SignatureHeader
  archive.signature_header := read_seven_zip_signature_header(fp);
  if (archive.signature_header.major_version = 0) and (archive.signature_header.minor_version = 0) then
  begin
    Result.signature_header.major_version := 0;
    Result.parsed_header.streams_info.pack_info.number_pack_streams := 0;
    exit;
  end;

  // parse the header
  archive.parsed_header := read_seven_zip_next_header(fp, archive.signature_header.next_header_size, archive.signature_header.next_header_offset, res);
  if (res = UNDEF) then
  begin
    exit;
  end;

  Result := archive;
end;

function extract_hash_from_archive(fp: tstream; archive: tarchive; file_path: string; var res: integer): string;
var
  parsed_header: theader;
  signature_header: tsignature;
  streams_info: tstreams_info;
  unpack_info: tunpack_info;
  substreams_info: tsubstreams_info;
  digests: tdigests;
  // folders : array of tfolder;
  pack_info: tpack_info;
  hash_buf, data, attributes, codec_id, decompressed_header, compression_attributes: ansistring;

  folder: tfolder;

  position_after_header, position_pack, current_seek_position, folder_id, number_coders, coder_id, current_index, data_len, try_number, digests_index, length_difference, type_of_preprocessor, coder_pos, crc_len, aes_coder_idx, aes_coder_found, coders_idx, type_of_compression, type_of_data, num_pack_sizes, pack_size: integer;
  crc: cardinal;
  unpack_size : int64;
  digest: tdigest;

  salt_len, iv_len, number_cycles_power: integer;
  iv_buf, salt_buf, id: ansistring;
  coder: tcoder;

  has_encrypted_header_, is_truncated, padding_attack_possible, fl_coder: boolean;

  number_file_indices, number_streams, number_pack_info, number_folders, file_idx, data_offset, data_offset_tmp, stream_idx, next_file_idx, length_first_file, length_compressed, aes_len, AES_BLOCK_SIZE, folder_pos: integer;

  property_lclppb, dict_size_encoded, uncompressed_size_encoded, lzma_alone_format_header, status: ansistring;
  lzma_header : pansichar;
  header: theader;
  dict_size, lc, pb, lp: integer;
  output_buffer: array of byte;
  decompressed_header_stream: TMemoryStream;
  lzma_h : TLZMAHeader;
begin
  hash_buf := '';
  data := #0;

  // check if everything is defined/initialized
  // and retrieve the single "objects"

  // return undef unless (defined (archive));

  parsed_header := archive.parsed_header;
  // return undef unless (defined (parsed_header));

  signature_header := archive.signature_header;
  // return undef unless (defined (signature_header));

  streams_info := parsed_header.streams_info;

  // if (! defined (streams_info))
  // begin
  // show_empty_streams_info_warning (file_path);
  //
  // return undef;
  // end

  unpack_info := streams_info.unpack_info;
  // return undef unless (defined (unpack_info));

  substreams_info := streams_info.substreams_info;

  digests := unpack_info.digests;
  // return undef unless (defined (digests));

  // folders := unpack_info.folders;
  // return undef unless (defined (folders));

  pack_info := streams_info.pack_info;
  // return undef unless (defined (pack_info));

  // init file seek values

  position_after_header := signature_header.position_after_header;
  position_pack := pack_info.pack_pos;
  current_seek_position := position_after_header + position_pack;

  //
  // start:
  //

  // get first folder/coder

  folder_id := 0;

  folder := unpack_info.folders[folder_id];

  number_coders := folder.number_coders;

  // check if header is encrypted

  has_encrypted_header_ := False;

  if (number_coders > 1) then
  begin
    has_encrypted_header_ := False;
  end
  else
  begin
    has_encrypted_header_ := has_encrypted_header(folder);
  end;

  // get the first coder

  coder_id := 0;

  if (Length(folder.coders) = 0) then
  begin
    res := UNDEF;
    exit;
  end;

  coder := folder.coders[coder_id];
  // return undef unless (defined (coder));

  codec_id := coder.codec_id;
  // set index and seek to postition

  current_index := 0;

  my_seek(fp, current_seek_position, 0);

  // if it is lzma compressed, we need to decompress it first

  // ================= FOR USE LZMA1 NEED Compress::Raw::Lzma module of Perl ==================================

  if (codec_id = SEVEN_ZIP_LZMA1) then
  begin
    // get the sizes

    unpack_size := unpack_info.unpack_sizes[current_index];

    data_len := pack_info.pack_sizes[current_index];

    // get the data

    data := my_read(fp, data_len);

    // lzma "header" stuff

    attributes := coder.attributes;

    lzma_properties_decode(attributes, property_lclppb, lc, lp, pb, dict_size);

    if (Length(property_lclppb) <> 1) then
    begin
      res := UNDEF;
      exit;
    end;

    // the alone-format header is defined like this:
    //
    // +------------+----+----+----+----+--+--+--+--+--+--+--+--+
    // | Properties |  Dictionary Size  |   Uncompressed Size   |
    // +------------+----+----+----+----+--+--+--+--+--+--+--+--+
    //

    decompressed_header := '';

    // we loop over this code section max. 2 times to try two variants of headers (with the correct/specific values and with default values)

    for try_number := 1 to 2 do
    begin
      // (dict_size_encoded,uncompressed_size_encoded);
      // lz :=  new Compress::Raw::Lzma::AloneDecoder (AppendOutput := > 1);

      if (try_number = 1) then
      begin
        dict_size_encoded := lzma_alone_header_field_encode(dict_size, 4); // 4 bytes (the "Dictionary Size" field), little endian
        uncompressed_size_encoded := lzma_alone_header_field_encode(unpack_size, 8); // 8 bytes (the "Uncompressed Size" field), little endian
      end
      else
      begin
        // this is the fallback case (using some default values):
        dict_size_encoded := '00008000'; // "default" dictionary size (2^23 :=  0x00800000)
        uncompressed_size_encoded := 'ffffffffffffffff'; // means: unknown uncompressed size
      end;

      lzma_alone_format_header := property_lclppb + dict_size_encoded + uncompressed_size_encoded;

      lzma_h.PropertyData[0]  := byte(ord(property_lclppb[1]));
      lzma_h.PropertyData[1]  := byte(lc);
      lzma_h.PropertyData[2]  := byte(lp);
      lzma_h.PropertyData[3]  := byte(pb);
      lzma_h.PropertyData[4]  := byte(dict_size);
      lzma_h.UncompressedSize := unpack_size;

      getmem(lzma_header, sizeof(lzma_h)+length(data));
      CopyMemory(lzma_header, @lzma_h, sizeof(lzma_h));
      inc(lzma_header, sizeof(lzma_h));
      CopyMemory(lzma_header, @data[1], length(data));
      dec(lzma_header, sizeof(lzma_h));

      setlength(output_buffer, unpack_size);
      try
        LzmaDecodeBuffer(lzma_header, length(lzma_alone_format_header + data), output_buffer);
      except
        on E : Exception do begin
          WriteLn(ErrOutput, E.message);
          res := UNDEF;
          exit;
        end;
      end;

      if (Length(output_buffer) > 0) then
        break; // if we got some output it seems that it worked just fine
    end;

    if (Length(output_buffer) <= 0) then
    begin
      res := UNDEF;
      exit;
    end;

    // // in theory we should also check that the length is correct
    // // return undef unless (length (decompressed_header) = unpack_size);
    //
    // // check the decompressed 7zip header
    //
    memory_buffer_read_offset := 0; // decompressed_header is a new memory buffer (which uses a offset to speed things up)

    decompressed_header_stream := TMemoryStream.Create;
    decompressed_header_stream.Write(@output_buffer[0], length(output_buffer));
    id := read_id(decompressed_header_stream);

    if id <> SEVEN_ZIP_HEADER then
    begin
      res := UNDEF;
      exit;
    end;

    header := read_seven_zip_header(decompressed_header_stream, res); // !!!

    // override the "old" archive object

    archive.signature_header := signature_header;
    archive.parsed_header := header;

    parsed_header := archive.parsed_header;
    // return "" unless (defined (parsed_header));

    // this didn't change at all
    // signature_header := archive.signature_header;
    // return undef unless (defined (signature_header));

    streams_info := parsed_header.streams_info;

    // if (! defined (streams_info))
    // begin
    // show_empty_streams_info_warning (file_path);
    //
    // return "";
    // end

    unpack_info := streams_info.unpack_info;
    // return "" unless (defined (unpack_info));

    substreams_info := streams_info.substreams_info;

    digests := unpack_info.digests;
    // return "" unless (defined (digests));

    // folders := unpack_info.folders;
    // return "" unless (defined (folders));

    number_folders := unpack_info.number_folders;

    pack_info := streams_info.pack_info;
    // return "" unless (defined (pack_info));

    // loop over all folders/coders to check if we find an AES encrypted stream

    position_pack := pack_info.pack_pos;
    current_seek_position := position_after_header + position_pack; // reset the seek position

    fl_coder := False;
    for folder_pos := 0 to number_folders - 1 do
    begin
      if folder_pos >= Length(unpack_info.folders) then
        break;

      folder := unpack_info.folders[folder_pos];

      number_coders := folder.number_coders;

      num_pack_sizes := Length(pack_info.pack_sizes);

      for coder_pos := 0 to number_coders - 1 do
      begin
        if coder_pos >= Length(folder.coders) then
          break;
        coder := folder.coders[coder_pos];
        fl_coder := true;

        coder_id := coder_pos; // Attention: coder_id <> codec_id !

        codec_id := coder.codec_id;

        // we stop after first AES found, but in theory we could also deal
        // with several different AES streams (in that case we would need
        // to print several hash buffers, but this is a very special case)

        if (codec_id = SEVEN_ZIP_AES) then
          break;

        // ELSE: update seek position and index:

        if (current_index < num_pack_sizes) then // not all pack_sizes always need to be known (final ones can be skipped)
        begin
          pack_size := pack_info.pack_sizes[current_index];

          current_seek_position := current_seek_position + pack_size;
        end;

        inc(current_index);
      end;

      if (codec_id = SEVEN_ZIP_AES) then
        break;

      if not fl_coder then // last unless (defined(coder));
        break;
    end;

    // we unfortunately can't do anything if no AES encrypted data was found

    if (codec_id <> SEVEN_ZIP_AES) then
    begin
      WriteLn(ErrOutput, 'WARNING: no AES data found in the 7z file ' + file_path);
      Result := '';
      exit;
    end;
//    WriteLn(ErrOutput, 'ERROR: FOR USE LZMA1 NEED Compress::Raw::Lzma module of Perl');
//    Result := '';
//    exit;
  end
  else if (codec_id = SEVEN_ZIP_LZMA2) then
  begin
    write(ErrOutput, 'WARNING: lzma2 compression found within ' + file_path + ' is currently not supported, ');
    WriteLn(ErrOutput, 'but could be probably added easily');

    Result := '';
    exit;
  end
  else if (codec_id <> SEVEN_ZIP_AES) then
  begin
    WriteLn(ErrOutput, 'WARNING: unsupported coder with codec id ' + unpack_hex(codec_id) + ' in file ' + file_path + ' found.');
    WriteLn(ErrOutput, 'If you think this codec method from DOC/Methods.txt of the 7-Zip source code ');
    WriteLn(ErrOutput, 'should be supported, please file a problem report/feature request');

    Result := '';
    exit;
  end;

  //
  // finally: fill hash_buf
  //

  // first get the data with help of pack info

  unpack_size := unpack_info.unpack_sizes[current_index];

  data_len := pack_info.pack_sizes[current_index];

  digests_index := current_index; // correct ?

  // reset the file pointer to the position after signature header and get the data

  my_seek(fp, current_seek_position, 0);

  // get remaining hash info (iv, number cycles power)

  digest := get_digest(digests_index, unpack_info, substreams_info, res);

  if (res = UNDEF) or ((res <> UNDEF) and (not digest.defined)) then
  begin
    // return undef unless ((defined (digest)) && (digest.defined == 1));
    exit;
  end;

  attributes := coder.attributes;

  get_decoder_properties(attributes, salt_len, iv_len, iv_buf, salt_buf, number_cycles_power);

  crc := digest.crc;

  // special case: we can truncate the data_len and use 32 bytes in total for both iv + data (last 32 bytes of data)

  is_truncated := False;
  padding_attack_possible := False;

  data := '';
  if (not has_encrypted_header_) then
  begin
    length_difference := data_len - unpack_size;

    if (length_difference > 3) then
    begin
      if (data_len > (PASSWORD_RECOVERY_TOOL_DATA_LIMIT / 2)) then
      begin
        if (PASSWORD_RECOVERY_TOOL_SUPPORT_PADDING_ATTACK = 1) then
        begin
          my_seek(fp, data_len - 32, 1);

          iv_buf := my_read(fp, 16);
          iv_len := 16;

          data := my_read(fp, 16);
          data_len := 16;

          unpack_size := unpack_size mod 16;

          is_truncated := true;
        end
      end;

      padding_attack_possible := true;
    end
  end;

  type_of_compression := SEVEN_ZIP_UNCOMPRESSED;
  type_of_preprocessor := SEVEN_ZIP_UNCOMPRESSED;
  compression_attributes := '';

  for coder_pos := coder_id + 1 to number_coders - 1 do
  begin
    if Length(folder.coders) <= coder_pos then
      continue;
    // last unless (defined (coder));

    coder := folder.coders[coder_pos];

    codec_id := coder.codec_id;

    if (codec_id = SEVEN_ZIP_LZMA1) then
    begin
      type_of_compression := SEVEN_ZIP_LZMA1_COMPRESSED;
    end
    else if (codec_id = SEVEN_ZIP_LZMA2) then
    begin
      type_of_compression := SEVEN_ZIP_LZMA2_COMPRESSED;
    end
    else if (codec_id = SEVEN_ZIP_PPMD) then
    begin
      type_of_compression := SEVEN_ZIP_PPMD_COMPRESSED;
    end
    else if (codec_id = SEVEN_ZIP_BCJ) then
    begin
      type_of_preprocessor := SEVEN_ZIP_BCJ_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_BCJ2) then
    begin
      type_of_preprocessor := SEVEN_ZIP_BCJ2_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_PPC) then
    begin
      type_of_preprocessor := SEVEN_ZIP_PPC_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_IA64) then
    begin
      type_of_preprocessor := SEVEN_ZIP_IA64_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_ARM) then
    begin
      type_of_preprocessor := SEVEN_ZIP_ARM_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_ARMT) then
    begin
      type_of_preprocessor := SEVEN_ZIP_ARMT_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_SPARC) then
    begin
      type_of_preprocessor := SEVEN_ZIP_SPARC_PREPROCESSED;
    end
    else if (codec_id = SEVEN_ZIP_BZIP2) then
    begin
      type_of_compression := SEVEN_ZIP_BZIP2_COMPRESSED;
    end
    else if (codec_id = SEVEN_ZIP_DEFLATE) then
    begin
      type_of_compression := SEVEN_ZIP_DEFLATE_COMPRESSED;
    end;

    if (type_of_compression <> SEVEN_ZIP_UNCOMPRESSED) then
    begin
      if (coder.attributes <> #0) then
      begin
        compression_attributes := unpack_hex(coder.attributes);
      end
    end

    // writeln('Saw unknown codec ', codec_id);
  end;

  // show a warning if the decompression algorithm is currently not supported by the cracker

  if (SHOW_LZMA_DECOMPRESS_AFTER_DECRYPT_WARNING = 1) then
  begin
    if (type_of_compression <> SEVEN_ZIP_UNCOMPRESSED) then
    begin
      if (not is_truncated) then
      begin

        if (not(type_of_compression in PASSWORD_RECOVERY_TOOL_SUPPORTED_DECOMPRESSORS)) or ((type_of_preprocessor <> SEVEN_ZIP_UNCOMPRESSED) and (not type_of_preprocessor in PASSWORD_RECOVERY_TOOL_SUPPORTED_PREPROCESSORS)) then
        begin
          WriteLn(ErrOutput, 'WARNING: to correctly verify the CRC checksum of the data contained within the file ' + file_path + ',');
          WriteLn(ErrOutput, 'the data must be decompressed using ' + getName(type_of_compression));
          if type_of_preprocessor <> SEVEN_ZIP_UNCOMPRESSED then
            WriteLn(ErrOutput, ' and processed using ' + getName(type_of_preprocessor shl 4));
          WriteLn(ErrOutput, ' after the decryption step');
          WriteLn(ErrOutput, '');
          WriteLn(ErrOutput, 'PASSWORD_RECOVERY_TOOL_NAME currently does not support this particular decompression algorithm(s).');
          WriteLn(ErrOutput, '');

          if (padding_attack_possible) then
          begin
            WriteLn(ErrOutput, 'INFO: However there is also some good news in this particular case.');
            WriteLn(ErrOutput, 'Since AES-CBC is used by the 7z algorithm and the data length of this file allows a padding attack,');
            WriteLn(ErrOutput, 'the password recovery tool might be able to use that to verify the correctness of password candidates.');
            WriteLn(ErrOutput, 'By using this attack there might of course be a higher probability of false positives.');
            WriteLn(ErrOutput, '');
          end
          else if (type_of_compression = SEVEN_ZIP_LZMA2_COMPRESSED) then // this special case should only work for LZMA2
          begin
            if (data_len <= LZMA2_MIN_COMPRESSED_LEN) then
            begin
              WriteLn(ErrOutput, 'INFO: it might still be possible to crack the password of this archive since the data part seems');
              WriteLn(ErrOutput, 'to be very short and therefore it might use the LZMA2 uncompressed chunk feature');
              WriteLn(ErrOutput, '');
            end
          end
        end
      end
    end
  end;

  type_of_data := SEVEN_ZIP_UNCOMPRESSED; // this variable will hold the "number" after the "7z" hash signature

  if (is_truncated) then
  begin
    type_of_data := SEVEN_ZIP_TRUNCATED; // note: this means that we neither need the crc_len, nor the coder attributes
  end
  else
  begin
    type_of_data := (type_of_preprocessor shl 4) or type_of_compression;
  end;

  crc_len := 0;

  if (type_of_data <> SEVEN_ZIP_UNCOMPRESSED) and (type_of_data <> SEVEN_ZIP_TRUNCATED) then
  begin
    if (Length(substreams_info.unpack_sizes) > 0) then
    begin
      crc_len := substreams_info.unpack_sizes[0]; // default: use the first file of the first stream
    end
  end;

  if data = '' then
  begin
    if ((type_of_data <> SEVEN_ZIP_UNCOMPRESSED) and (type_of_data <> SEVEN_ZIP_TRUNCATED)) then
    begin
      if (ANALYZE_ALL_STREAMS_TO_FIND_SHORTEST_DATA_BUF = 1) then
      begin
        number_file_indices := Length(substreams_info.unpack_sizes);
        number_streams := Length(substreams_info.unpack_stream_numbers);
        number_pack_info := Length(pack_info.pack_sizes); // same as pack_info.number_pack_streams'end
        number_folders := Length(unpack_info.folders); // same as unpack_info.number_folders'end

        // check if there is a stream with a smaller first file than the first file of the first stream
        // (this is just a clever approach to produce shorter hashes)

        file_idx := 0;
        data_offset := 0;

        data_offset_tmp := 0;

        // sanity checks (otherwise we might overflow):

        if (number_pack_info < number_streams) then // should never happen (they should be equal)
        begin
          number_streams := number_pack_info;
        end;

        if (number_folders < number_streams) then // should never happen (they should be equal)
        begin
          number_streams := number_folders;
        end;

        for stream_idx := 0 to number_streams - 1 do
        begin
          next_file_idx := substreams_info.unpack_stream_numbers[stream_idx];

          length_first_file := substreams_info.unpack_sizes[file_idx];

          length_compressed := pack_info.pack_sizes[stream_idx];

          if (SHOW_LIST_OF_ALL_STREAMS = 1) then
          begin
            WriteLn(ErrOutput, 'DEBUG: new stream found with first file consisting of %9d bytes of %10d bytes total stream length', length_first_file, length_compressed);
          end;

          if (length_first_file < crc_len) then
          begin
            digest := get_digest(file_idx, unpack_info, substreams_info, res);

            if (not digest.defined) then
            begin
              continue;
              // next unless ();
            end;

            // get new AES settings (salt, iv, costs):

            // coders := unpack_info.folders[stream_idx].coders;

            aes_coder_idx := 0;
            aes_coder_found := 0;

            for coders_idx := 0 to number_coders - 1 do
            begin
              if (Length(unpack_info.folders[stream_idx].coders) <= coders_idx) then
                continue;
              // next unless defined @coders[coders_idx];

              codec_id := unpack_info.folders[stream_idx].coders[coders_idx].codec_id;

              if (codec_id = SEVEN_ZIP_AES) then
              begin
                aes_coder_idx := coders_idx;

                aes_coder_found := 1;
              end
              else if (unpack_info.folders[stream_idx].coders[coders_idx].attributes <> '') then
              begin
                compression_attributes := unpack_hex(unpack_info.folders[stream_idx].coders[coders_idx].attributes);
              end
            end;

            // next unless ($aes_coder_found == 1);
            if aes_coder_found <> 1 then
              continue;

            attributes := unpack_info.folders[stream_idx].coders[aes_coder_idx].attributes;

            //
            // set the "new" hash properties (for this specific/better stream with smaller first file):
            //

            get_decoder_properties(attributes, salt_len, iv_len, iv_buf, salt_buf, number_cycles_power);

            crc := digest.crc;

            crc_len := length_first_file;

            data_len := length_compressed;

            unpack_size := length_first_file;

            data_offset := data_offset_tmp;

            // we assume that type_of_data and type_of_compression didn't change between the streams
            // (this should/could be checked too to avoid any strange problems)
          end;

          file_idx := file_idx + next_file_idx;

          if (file_idx >= number_file_indices) then // should never happen
          begin
            break;
          end;

          data_offset_tmp := data_offset_tmp + length_compressed;
        end;

        if (SHOW_LIST_OF_ALL_STREAMS = 1) then
        begin
          WriteLn(ErrOutput, 'DEBUG: shortest file at the beginning of a stream consists of ', crc_len, ' bytes (offset: ', data_offset, ' bytes)');
        end;

        if (data_offset > 0) then
        begin
          my_seek(fp, data_offset, 1);
        end
      end;

      if (SHORTEN_HASH_LENGTH_TO_CRC_LENGTH = 1) then
      begin
        aes_len := trunc(SHORTEN_HASH_FIXED_HEADER + crc_len + SHORTEN_HASH_EXTRA_PERCENT / 100 * crc_len);

        AES_BLOCK_SIZE := 16;

        aes_len := aes_len + AES_BLOCK_SIZE - 1; // add these bytes to be sure to always include the last "block" too (round up and cast)

        aes_len := trunc(aes_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

        if (aes_len < data_len) then
        begin
          data_len := aes_len;
          unpack_size := aes_len;
        end
      end
    end;

    data := my_read(fp, data_len); // NOTE: we shouldn't read a very huge data buffer directly into memory
    // improvement: read the data in chunks of several MBs and keep printing it
    // directly to stdout (by also not returning a string from this function)
    // that would help to achieve minimal RAM consumption (even for very large hashes)
  end;

  if (Length(data) <> data_len) then
  begin
    res := UNDEF;
    exit;
    // return undef unless ();
  end;

  if (data_len > (PASSWORD_RECOVERY_TOOL_DATA_LIMIT / 2)) then
  begin
    WriteLn(ErrOutput, 'WARNING: the file ' + file_path + ' unfortunately can`t be used with PASSWORD_RECOVERY_TOOL_NAME since the data length');
    WriteLn(ErrOutput, 'in this particular case is too long (data_len of the maximum allowed ', PASSWORD_RECOVERY_TOOL_DATA_LIMIT / 2, ' bytes)');

    if (PASSWORD_RECOVERY_TOOL_SUPPORT_PADDING_ATTACK = 1) then
    begin
      WriteLn(ErrOutput, 'Furthermore, it could not be truncated. This should only happen in very rare cases');
    end;
    Result := '';
    exit;
  end;

  if PASSWORD_RECOVERY_TOOL_NAME = 'john' then
    hash_buf := file_path + ':' + hash_buf;

  hash_buf := hash_buf + format('%s%u$%u$%u$%s$%u$%s$%u$%u$%u$%s', [SEVEN_ZIP_HASH_SIGNATURE, type_of_data, number_cycles_power, salt_len, unpack_hex(salt_buf), iv_len, unpack_hex(iv_buf), crc, data_len, unpack_size, unpack_hex(data) // could be very large. We could/should avoid loading/copying this data into memory
    ]);

  if (type_of_data = SEVEN_ZIP_UNCOMPRESSED) then
  begin
    Result := hash_buf;
    exit;
  end;
  if (type_of_data = SEVEN_ZIP_TRUNCATED) then
  begin
    Result := hash_buf;
    exit;
  end;

  hash_buf := hash_buf + format('$%u$%s', [crc_len, compression_attributes]);
  Result := hash_buf;
end;

//
// SFX related helper functions
//

// The strategy here is as follows:
// 1. only use sfx-checks whenever the 7z header is not at start (i.e. if parsing of a "regular" 7z failed)
// 2. try to read PE
// 3. try to search for $SEVEN_ZIP_MAGIC within the 512 bytes bounderies
// 4. try to do a full scan ($SEVEN_ZIP_MAGIC_LEN bytes at a time)

// sfx_7z_pe_search () searches for the 7z signature by seeking to the correct offset in the PE file
// (e.g. after the PE stub aka the executable part)
function sfx_7z_pe_search(fp: tstream): boolean;
var
  bytes: ansistring;
  i, section_farthest, pos_after_farthest_section: integer;
  e_lfanew, size_of_raw_data, pointer_to_raw_data: uint32;
  num_sections: USHORT;
begin
  Result := False;

  // 1. DOS header (e_lfanew)
  // 2. Portable executable (PE) headers (NumberOfSections)
  // 3. Section headers (PointerToRawData + SizeOfRawData)

  // we assume that the file is a common/standard PE executable, we will do some checks:

  // DOS header

  // we should have a MS-DOS MZ executable

  bytes := my_read(fp, 2);

  if (Length(bytes) <> 2) then
  begin
    Result := False;
    exit;
  end;
  if (bytes <> 'MZ') then
  begin
    Result := False;
    exit;
  end; // 0x5a4d
  if (Length(my_read(fp, 58)) <> 58) then
  begin
    Result := False;
    exit;
  end;

  bytes := my_read(fp, 4);

  if (Length(bytes) <> 4) then
  begin
    Result := False;
    exit;
  end;

  Move(bytes, e_lfanew, 4);
  // e_lfanew := unpack ("L", bytes);

  my_seek(fp, e_lfanew, 0);

  // PE header

  bytes := my_read(fp, 4); // PE0000 signature after DOS part

  if (Length(bytes) <> 4) then
  begin
    Result := False;
    exit;
  end;
  if (bytes <> 'PE'#0#0) then
  begin
    Result := False;
    exit;
  end;
  if (Length(my_read(fp, 2)) <> 2) then
  begin
    Result := False;
    exit;
  end; // skip FileHeader.Machine

  bytes := my_read(fp, 2);

  if (Length(bytes) <> 2) then
  begin
    Result := False;
    exit;
  end;

  // num_sections := unpack ("S", bytes);
  Move(bytes, num_sections, 2);

  if (num_sections < 1) then
  begin
    Result := False;
    exit;
  end;

  if (Length(my_read(fp, 16)) <> 16) then
  begin
    Result := False;
    exit;
  end; // skip rest of FileHeader
  if (Length(my_read(fp, 224)) <> 224) then
  begin
    Result := False;
    exit;
  end; // skip OptionalHeader

  section_farthest := 0;
  pos_after_farthest_section := 0;

  for i := 0 to num_sections - 1 do
  begin
    // we loop through all the section headers

    // name := my_read (fp, 8); return 0 if (length (my_read (fp, 8)) <> 8);
    if (Length(my_read(fp, 16)) <> 16) then
    begin
      Result := False;
      exit;
    end; // skip Name, Misc, VirtualAddress, SizeOfRawData

    // SizeOfRawData

    bytes := my_read(fp, 4);

    if (Length(bytes) <> 4) then
    begin
      Result := False;
      exit;
    end;

    // size_of_raw_data := unpack ("L", bytes);
    Move(bytes, size_of_raw_data, 4);

    // PointerToRawData

    bytes := my_read(fp, 4);

    if (Length(bytes) <> 4) then
    begin
      Result := False;
      exit;
    end;

    // pointer_to_raw_data := unpack ("L", bytes);
    Move(bytes, pointer_to_raw_data, 4);

    // the sections are not quaranteed to be ordered (:=> compare all of them!)

    if (pointer_to_raw_data > section_farthest) then
    begin
      section_farthest := pointer_to_raw_data;

      pos_after_farthest_section := pointer_to_raw_data + size_of_raw_data;
    end;

    // loop to next SectionTable entry

    if (Length(my_read(fp, 16)) <> 16) then
    begin
      Result := False;
      exit;
    end; // skip rest of SectionHeader
  end;

  // check if 7z signature found (after stub)

  my_seek(fp, pos_after_farthest_section, 0);

  bytes := my_read(fp, SEVEN_ZIP_MAGIC_LEN);

  if (Length(bytes) <> SEVEN_ZIP_MAGIC_LEN) then
  begin
    Result := False;
    exit;
  end;

  if (bytes = SEVEN_ZIP_MAGIC) then
  begin
    Result := true;
  end
end;

// sfx_7z_512_search () searches for the 7z signature by only looking at every 512 byte boundery
function sfx_7z_512_search(fp: tstream): boolean;
var
  seek_skip, len_bytes: integer;
  bytes: ansistring;
begin
  Result := False;
  seek_skip := 512 - SEVEN_ZIP_MAGIC_LEN;

  bytes := my_read(fp, SEVEN_ZIP_MAGIC_LEN);

  len_bytes := Length(bytes);

  while (len_bytes = SEVEN_ZIP_MAGIC_LEN) do
  begin
    if (bytes = SEVEN_ZIP_MAGIC) then
    begin
      Result := true;
      break;
    end;

    my_seek(fp, seek_skip, 1);

    bytes := my_read(fp, SEVEN_ZIP_MAGIC_LEN);

    len_bytes := Length(bytes);
  end;
end;

// sfx_7z_full_search () searches for the 7z signature by looking at every byte in the file
// (this type of search should only be performed if no other variant worked)
function sfx_7z_full_search(fp: tstream; var prev_idx_into_magic: integer): boolean;
var
  idx_into_magic, len_bytes, i: integer;
  bytes, c: ansistring;
begin
  Result := False;

  idx_into_magic := 0;
  prev_idx_into_magic := 0;

  len_bytes := SEVEN_ZIP_MAGIC_LEN;

  while (len_bytes = SEVEN_ZIP_MAGIC_LEN) do
  begin
    bytes := my_read(fp, SEVEN_ZIP_MAGIC_LEN);

    if (Length(bytes) = 0) then
      break;

    prev_idx_into_magic := idx_into_magic;

    if (bytes = SEVEN_ZIP_MAGIC) then
    begin
      Result := true;
      break;
    end;

    for i := 0 to Length(bytes) - 1 do
    begin
      c := copy(bytes, i + 1, 1);

      if (c <> copy(SEVEN_ZIP_MAGIC, idx_into_magic + 1, 1)) then
      begin
        idx_into_magic := 0; // reset
      end
      else
      begin
        inc(idx_into_magic);

        if (idx_into_magic = SEVEN_ZIP_MAGIC_LEN) then
        begin
          Result := true;
          break;
        end
      end
    end;

    if (Result) then
      break;

    len_bytes := Length(bytes);
  end;
end;

function sfx_get_hash(fp: tstream; file_path: string): string;
var
  hash_buf: string;
  cur_pos, res, file_size, full_search_idx: integer;
  db_positions_analysed: TDictionary<integer, boolean>;
  archive: tarchive;
begin
  hash_buf := '';

  db_positions_analysed := TDictionary<integer, boolean>.Create;
  // holds a list of offsets that we already tried to parse
  try
    // we make the assumption that there is max one .7z file within the .sfx!

    // Variant 1 (PE file structure parsing)

    my_seek(fp, 0, 0);

    if (sfx_7z_pe_search(fp)) then
    begin
      cur_pos := my_tell(fp);

      db_positions_analysed.Add(cur_pos, true); // mark it as analyzed

      archive := read_seven_zip_archive(fp, res);

      hash_buf := extract_hash_from_archive(fp, archive, file_path, res);

      if (Length(hash_buf) > 0) then
      begin
        Result := hash_buf;
        exit;
      end
    end;

    // Variant 2 (search only at the 512 bytes bounderies)

    my_seek(fp, 512, 0);

    while (sfx_7z_512_search(fp)) do
    begin
      cur_pos := my_tell(fp);

      if (not db_positions_analysed.ContainsKey(cur_pos)) then
      begin
        db_positions_analysed.Add(cur_pos, true); // mark it as analyzed

        archive := read_seven_zip_archive(fp, res);

        hash_buf := extract_hash_from_archive(fp, archive, file_path, res);

        if (Length(hash_buf) > 0) then
        begin
          Result := hash_buf;
          exit;
        end
      end;

      if (my_seek(fp, cur_pos + 512 - SEVEN_ZIP_MAGIC_LEN, 0) <> 1) then
        break;
    end;

    // Variant 3 (full search - worst case - shouldn't happen at all with a standard .sfx)

    my_seek(fp, 0, 2);

    file_size := my_tell(fp);

    if (file_size > 8 * 1024 * 1024) then // let's say that 8 MiB is already a huge file
    begin
      WriteLn(ErrOutput, 'WARNING: searching for the 7z signature in a file_size bytes long file (' + file_path + ') might take some time');
    end;

    my_seek(fp, 1, 0); // we do no that the signature is not at position 0, so we start at 1

    while (sfx_7z_full_search(fp, full_search_idx)) do
    begin
      cur_pos := my_tell(fp);

      cur_pos := cur_pos - full_search_idx;

      my_seek(fp, cur_pos, 0); // we might not be there yet (depends if full_search_idx <> 0)

      if (not db_positions_analysed.ContainsKey(cur_pos)) then
      begin
        // we can skip the database updates because it's our last try to find the 7z file
        // db_positions_analysed.Add(cur_pos, true);

        archive := read_seven_zip_archive(fp, res);

        hash_buf := extract_hash_from_archive(fp, archive, file_path, res);

        if (Length(hash_buf) > 0) then
        begin
          Result := hash_buf;
          exit;
        end
      end;

      my_seek(fp, cur_pos, 0); // seek back to position JUST AFTER the previously found signature
    end;

    // in theory if we reach this code section we already know that parsing the file failed (but let's confirm it)

    if (Length(hash_buf) > 0) then
    begin
      WriteLn(ErrOutput, 'WARNING: the file ' + file_path + ' is neither a supported 7-Zip file nor a supported SFX file');
    end;
  finally
    db_positions_analysed.Free;
  end;

  // cleanup
  fp.Free;

  Result := hash_buf;
end;

function seven_zip_get_hash(file_path: string; var res: integer): string;
var
  hash_buf: string;
  seven_zip_file: tstream;
  archive: tarchive;
begin
  hash_buf := '';

  // open file for reading
  try
    seven_zip_file := TFileStream.Create(file_path, fmOpenRead);
  except
    WriteLn(ErrOutput, 'WARNING: could not open the file ' + file_path + ' for reading');
    seven_zip_file := nil;
  end;
  // binmode ($seven_zip_file);
  if (seven_zip_file <> nil) then
  begin

    // check if valid and supported 7z file

    if (not is_supported_seven_zip_file(seven_zip_file)) then
    begin
      Result := sfx_get_hash(seven_zip_file, file_path);
      exit;
    end;

    archive := read_seven_zip_archive(seven_zip_file, res);

    hash_buf := extract_hash_from_archive(seven_zip_file, archive, file_path, res);

    // cleanup
    seven_zip_file.Free;
  end;

  Result := hash_buf;
end;

function get_ordered_splitted_file_list(files: TArrayStrings): TArrayStrings;
var
  failed: boolean;
  num_probably_splitted_files: integer;
  current_extension, file_prefix, file_name, prefix, extension: string;
  i, extension_length, idx_extension: integer;
  v, Code: integer;
  list: TStringList;
begin
  if Length(files) <= 0 then
  begin
    SetLength(Result, 0);
    exit;
  end;

  failed := False;
  num_probably_splitted_files := 0;

  file_prefix := '';
  extension_length := 0;

  for i := 0 to Length(files) - 1 do
  begin
    file_name := files[i];
    idx_extension := pos('.', file_name);

    if (idx_extension <= 0) then
    begin
      failed := true;
      break;
    end;

    prefix := copy(file_name, 0, idx_extension);
    extension := copy(file_name, idx_extension + 1);

    if (Length(prefix) = 0) then
    begin
      failed := False;
      break;
    end;

    // detect change in file prefix (the actual "name")

    if (Length(file_prefix) = 0) then // init
    begin
      file_prefix := prefix;
    end;

    if (prefix <> file_prefix) then
    begin
      failed := False;
      break;
    end;

    // check extensions (should be numbers only)
    val(extension, v, Code);
    if (Code <> 0) then
    begin
      failed := true;
      break;
    end;

    if (extension_length = 0) then // init
    begin
      extension_length := Length(extension);
    end;

    if (Length(extension) <> extension_length) then
    begin
      failed := False;
      break;
    end;

    inc(num_probably_splitted_files);
  end;

  if (Length(file_prefix) <= 0) then
  begin
    SetLength(Result, 0);
    exit;
  end;
  // return () unless (length ($file_prefix) > 0);
  if (extension_length <= 0) then
  begin
    SetLength(Result, 0);
    exit;
  end;
  // return () unless ($extension_length > 0);

  if (failed) then
  begin
    if (num_probably_splitted_files > 1) then
    begin
      WriteLn(ErrOutput, 'WARNING: it seems that some files could be part of a splitted 7z archive named ' + file_prefix);
      WriteLn(ErrOutput, 'ATTENTION: make sure to only specify the files belonging to the splitted archive (do not combine them with other archives)');
    end;
    SetLength(Result, 0);
    exit;
  end;

  // sort the list and check if there is no missing file
  // (at this point in time we can't verify if the last file is really the last one)

  list := TStringList.Create();
  for i := 0 to Length(files) - 1 do
    list.Add(files[i]);

  try
    list.Sort;
    SetLength(Result, list.Count);
    for i := 0 to list.Count - 1 do
      Result[i] := list[i];
  finally
    list.Free;
  end;

  if (Length(Result) <= 0) or (Length(Result) <> Length(files)) then
  begin
    SetLength(Result, 0);
    exit;
  end;

  for i := 0 to Length(Result) - 1 do
  begin
    current_extension := inttostr(i + 1);
    while Length(current_extension) <> extension_length do
      current_extension := '0' + current_extension;

    if (Result[i] <> file_prefix + current_extension) then
    begin
      SetLength(Result, 0);
      exit;
    end;
  end
end;

function get_file_sizes_list(files: TArrayStrings): tfiles_with_sizes;
var
  files_with_sizes: tfiles_with_sizes;
  accumulated_size: cardinal;
  info: TWin32FileAttributeData;
  Count: integer;
  file_: string;
begin
  accumulated_size := 0;

  SetLength(files_with_sizes, 1);
  for Count := 0 to Length(files) - 1 do
  begin
    file_ := files[Count];

    if not GetFileAttributesEx(PWideChar(file_), GetFileExInfoStandard, @info) then
    begin
      WriteLn(ErrOutput, 'ERROR: could not get the file size of the file ' + file_);
      Halt(1);
    end;

    files_with_sizes[0].fh := nil; // the file handle
    files_with_sizes[0].num := 0;

    SetLength(files_with_sizes, Length(files_with_sizes) + 1);
    files_with_sizes[Count + 1].name := file_;
    files_with_sizes[Count + 1].size := Int64(info.nFileSizeLow) or Int64(info.nFileSizeHigh shl 32);
    files_with_sizes[Count + 1].start := accumulated_size;

    accumulated_size := accumulated_size + (Int64(info.nFileSizeLow) or Int64(info.nFileSizeHigh shl 32));
  end;

  Result := files_with_sizes;
end;

function splitted_seven_zip_open(files: TArrayStrings): integer;
var
  sorted_file_list: TArrayStrings;
  first_splitted_file: string;
  file_list_with_sizes: tfiles_with_sizes;
  seven_zip_file: tstream;
  archive: tarchive;
  res: integer;
begin
  sorted_file_list := get_ordered_splitted_file_list(files);

  if (Length(sorted_file_list) <= 0) then
  begin
    Result := 0;
    exit;
  end;

  file_list_with_sizes := get_file_sizes_list(sorted_file_list);

  // start to parse the file list

  memory_buffer_read_offset := 0; // just to be safe

  first_splitted_file := file_list_with_sizes[1].name;

  hash_buf := '';

  // open file for reading
  try
    seven_zip_file := TFileStream.Create(first_splitted_file, fmOpenRead);
  except
    WriteLn(ErrOutput, 'ERROR: could not open the the splitted archive file ' + first_splitted_file + ' for reading');
    Halt(1);
  end;

  // binmode ($seven_zip_file);

  file_list_with_sizes[0].fh := seven_zip_file;
  file_list_with_sizes[0].num := 1; // meaning is: "first file"

  // check if valid and supported 7z file

  if (not is_supported_seven_zip_file(file_list_with_sizes[0].fh)) then
  begin
    WriteLn(ErrOutput, 'ERROR: the splitted archive file ' + first_splitted_file + ' is not a valid 7z file');
    Halt(1);
  end;

  archive := read_seven_zip_archive(file_list_with_sizes[0].fh, res);

  hash_buf := extract_hash_from_archive(file_list_with_sizes[0].fh, archive, first_splitted_file, res);

  // cleanup

  seven_zip_file.Free;

  if (hash_buf <> '') then
  begin
    if (Length(hash_buf) > 0) then
    begin
      WriteLn(hash_buf);
    end
  end;

  Result := 1;
end;

//
// Start
//
begin
  for i := 1 to ParamCount do
  begin
    if (ParamStr(i) = '--skip-sensitive-data-warning') then
    begin
      display_sensitive_warning := 0;
    end
    else
    begin
      SetLength(file_parameters, Length(file_parameters) + 1);
      file_parameters[Length(file_parameters) - 1] := ParamStr(i);
    end
  end;

  if (Length(file_parameters) < 1) then
  begin
    usage();
    Halt(1);
  end;

  first_file := 1;

  SetLength(file_list, Length(file_parameters));
  Move(file_parameters, file_list, Length(file_list));

  // file_list := globbing_on_windows (file_parameters);

  // try to handle this special case: splitted .7z files (.7z.001, .7z.002, .7z.003, ...)
  // ATTENTION: there is one restriction here: splitted archives shouldn't be combined with other
  // splitted or non-splitted archives

  was_splitted := splitted_seven_zip_open(file_list);

  if (was_splitted = 1) then
  begin
    Halt(0);
  end;

  // "non-splitted" file list:

  for i := 0 to Length(file_list) - 1 do
  begin
    if (not FileExists(file_list[i])) then
    begin
      WriteLn(ErrOutput, 'WARNING: could not open file ' + file_list[i]);
      continue;
    end;

    hash_buf := seven_zip_get_hash(file_list[i], res);

    // next unless (defined ($hash_buf));
    // next unless (length ($hash_buf) > 0);
    if (hash_buf = '') then
      continue;

    if (display_sensitive_warning = 1) then
    begin
      if (first_file = 1) then
      begin
        WriteLn(ErrOutput, 'ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes');
        first_file := 0;
      end
    end;

    WriteLn(hash_buf);
  end;

  Halt(0);

end.
