const std = @import("std");
const Io = std.Io;
const ff = std.crypto.ff;

const chunk_data_size = 117;
const padding_size = 11;
const padded_size = chunk_data_size + padding_size;
pub const sign_size: usize = 64;

pub fn paddedLength(plaintext_len: usize) usize {
    return (std.math.divCeil(usize, plaintext_len, chunk_data_size) catch unreachable) * padded_size;
}

pub fn encrypt(public_key_der: []const u8, plaintext: []const u8, output: []u8) !void {
    const key = PublicKey.fromDer(public_key_der) catch return error.InvalidPublicKey;
    const num_chunks = std.math.divCeil(usize, plaintext.len, chunk_data_size) catch unreachable;

    for (0..num_chunks) |n| {
        const plainChunk = plaintext[n * chunk_data_size .. @min((n + 1) * chunk_data_size, plaintext.len)];
        _ = key.encryptPkcsv1_5(plainChunk, output[n * padded_size .. (n + 1) * padded_size]) catch unreachable;
    }
}

pub fn decrypt(private_key_der: []const u8, ciphertext: []const u8, output: []u8) ![]const u8 {
    const key = KeyPair.fromDer(private_key_der) catch return error.InvalidPrivateKey;
    return try key.decryptPkcsv1_5(ciphertext, output);
}

pub fn sign(private_key_der: []const u8, plaintext: []const u8, output: *[sign_size]u8) !void {
    const key = KeyPair.fromDer(private_key_der) catch return error.InvalidPrivateKey;
    _ = key.signPkcsv1_5(std.crypto.hash.sha2.Sha256, plaintext, output) catch unreachable;
}

const max_modulus_bits = 4096;
const max_modulus_len = max_modulus_bits / 8;

const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;
const Index = usize;

pub const ValueError = error{
    Modulus,
    Exponent,
};

const PublicKey = struct {
    modulus: Modulus,
    public_exponent: Fe,

    pub const FromBytesError = ValueError || ff.OverflowError || ff.FieldElementError || ff.InvalidModulusError || error{InsecureBitCount};

    pub fn fromBytes(mod: []const u8, exp: []const u8) FromBytesError!PublicKey {
        const modulus = try Modulus.fromBytes(mod, .big);
        const public_exponent = try Fe.fromBytes(modulus, exp, .big);

        if (std.debug.runtime_safety) {
            const e_v = public_exponent.toPrimitive(u32) catch return error.Exponent;
            if (!public_exponent.isOdd()) return error.Exponent;
            if (e_v < 3) return error.Exponent;
            if (modulus.v.compare(public_exponent.v) == .lt) return error.Exponent;
        }

        return .{ .modulus = modulus, .public_exponent = public_exponent };
    }

    pub fn fromDer(bytes: []const u8) (Parser.Error || FromBytesError)!PublicKey {
        var parser = Parser{ .bytes = bytes };

        const seq = try parser.expectSequence();
        defer parser.seek(seq.slice.end);

        const modulus = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        try parser.expectEnd(seq.slice.end);
        try parser.expectEnd(bytes.len);

        return try fromBytes(parser.view(modulus), parser.view(pub_exp));
    }

    pub fn encryptPkcsv1_5(pk: PublicKey, msg: []const u8, out: []u8) ![]const u8 {
        const k = byteLen(pk.modulus.bits());
        if (out.len < k) return error.BufferTooSmall;
        if (msg.len > k - 11) return error.MessageTooLong;

        var em = out[0..k];
        em[0] = 0;
        em[1] = 2;

        const ps = em[2..][0 .. k - msg.len - 3];
        for (ps) |*v| {
            v.* = std.crypto.random.uintLessThan(u8, 0xff) + 1;
        }

        em[em.len - msg.len - 1] = 0;
        @memcpy(em[em.len - msg.len ..][0..msg.len], msg);

        const m = try Fe.fromBytes(pk.modulus, em, .big);
        const e = try pk.modulus.powPublic(m, pk.public_exponent);
        try e.toBytes(em, .big);
        return em;
    }
};

fn byteLen(bits: usize) usize {
    return std.math.divCeil(usize, bits, 8) catch unreachable;
}

const SecretKey = struct {
    private_exponent: Fe,

    pub const FromBytesError = ValueError || ff.OverflowError || ff.FieldElementError;

    pub fn fromBytes(n: Modulus, exp: []const u8) FromBytesError!SecretKey {
        const d = try Fe.fromBytes(n, exp, .big);
        if (std.debug.runtime_safety) {
            if (!d.isOdd()) return error.Exponent;
            if (d.v.compare(n.v) != .lt) return error.Exponent;
        }

        return .{ .private_exponent = d };
    }
};

const KeyPair = struct {
    public: PublicKey,
    secret: SecretKey,

    pub const FromDerError = PublicKey.FromBytesError || SecretKey.FromBytesError || Parser.Error || error{ KeyMismatch, InvalidVersion };

    pub fn fromDer(bytes: []const u8) FromDerError!KeyPair {
        var parser = Parser{ .bytes = bytes };
        const seq = try parser.expectSequence();
        const version = try parser.expectInt(u8);

        const mod = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);
        const sec_exp = try parser.expectPrimitive(.integer);

        const public = try PublicKey.fromBytes(parser.view(mod), parser.view(pub_exp));
        const secret = try SecretKey.fromBytes(public.modulus, parser.view(sec_exp));

        const prime1 = try parser.expectPrimitive(.integer);
        const prime2 = try parser.expectPrimitive(.integer);
        const exp1 = try parser.expectPrimitive(.integer);
        const exp2 = try parser.expectPrimitive(.integer);
        const coeff = try parser.expectPrimitive(.integer);
        _ = .{ exp1, exp2, coeff };

        switch (version) {
            0 => {},
            1 => {
                _ = try parser.expectSequenceOf();
                while (!parser.eof()) {
                    _ = try parser.expectSequence();
                    const ri = try parser.expectPrimitive(.integer);
                    const di = try parser.expectPrimitive(.integer);
                    const ti = try parser.expectPrimitive(.integer);
                    _ = .{ ri, di, ti };
                }
            },
            else => return error.InvalidVersion,
        }

        try parser.expectEnd(seq.slice.end);
        try parser.expectEnd(bytes.len);

        if (std.debug.runtime_safety) {
            const p = try Fe.fromBytes(public.modulus, parser.view(prime1), .big);
            const q = try Fe.fromBytes(public.modulus, parser.view(prime2), .big);

            const expected_zero = public.modulus.mul(p, q);
            if (!expected_zero.isZero()) return error.KeyMismatch;
        }

        return .{ .public = public, .secret = secret };
    }

    pub fn signPkcsv1_5(kp: KeyPair, comptime Hash: type, msg: []const u8, out: []u8) !PKCS1v1_5(Hash).Signature {
        var st = try signerPkcsv1_5(kp, Hash);
        st.update(msg);
        return try st.finalize(out);
    }

    pub fn signerPkcsv1_5(kp: KeyPair, comptime Hash: type) !PKCS1v1_5(Hash).Signer {
        return PKCS1v1_5(Hash).Signer.init(kp);
    }

    pub fn decryptPkcsv1_5(kp: KeyPair, ciphertext: []const u8, out: []u8) ![]const u8 {
        const k = byteLen(kp.public.modulus.bits());
        if (out.len < k) return error.BufferTooSmall;

        const em = out[0..k];

        const m = try Fe.fromBytes(kp.public.modulus, ciphertext, .big);
        const e = try kp.public.modulus.pow(m, kp.secret.private_exponent);
        try e.toBytes(em, .big);

        const msg_start = ct.lastIndexOfScalar(em, 0) orelse em.len;
        return em[msg_start + 1 ..];
    }

    pub fn encrypt(kp: KeyPair, plaintext: []const u8, out: []u8) !void {
        const n = kp.public.modulus;
        const k = byteLen(n.bits());
        if (plaintext.len > k) return error.MessageTooLong;

        const msg_as_int = try Fe.fromBytes(n, plaintext, .big);
        const enc_as_int = try n.pow(msg_as_int, kp.secret.private_exponent);
        try enc_as_int.toBytes(out, .big);
    }
};

fn PKCS1v1_5(comptime Hash: type) type {
    return struct {
        const PkcsT = @This();
        pub const Signature = struct {
            bytes: []const u8,

            const Self = @This();

            pub fn verifier(self: Self, public_key: PublicKey) !Verifier {
                return Verifier.init(self, public_key);
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey) !void {
                var st = Verifier.init(self, public_key);
                st.update(msg);
                return st.verify();
            }
        };

        pub const Signer = struct {
            h: Hash,
            key_pair: KeyPair,

            fn init(key_pair: KeyPair) Signer {
                return .{
                    .h = Hash.init(.{}),
                    .key_pair = key_pair,
                };
            }

            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            pub fn finalize(self: *Signer, out: []u8) !PkcsT.Signature {
                const k = byteLen(self.key_pair.public.modulus.bits());
                if (out.len < k) return error.BufferTooSmall;

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                const em = try emsaEncode(hash, out[0..k]);
                try self.key_pair.encrypt(em, em);
                return .{ .bytes = em };
            }
        };

        pub const Verifier = struct {
            h: Hash,
            sig: PkcsT.Signature,
            public_key: PublicKey,

            fn init(sig: PkcsT.Signature, public_key: PublicKey) Verifier {
                return Verifier{
                    .h = Hash.init(.{}),
                    .sig = sig,
                    .public_key = public_key,
                };
            }

            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Verifier) !void {
                const pk = self.public_key;
                const s = try Fe.fromBytes(pk.modulus, self.sig.bytes, .big);
                const emm = try pk.modulus.powPublic(s, pk.public_exponent);

                var em_buf: [max_modulus_len]u8 = undefined;
                const em = em_buf[0..byteLen(pk.modulus.bits())];
                try emm.toBytes(em, .big);

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                var em_buf2: [max_modulus_len]u8 = undefined;
                const expected_em = try emsaEncode(hash, em_buf2[0..byteLen(pk.modulus.bits())]);
                if (!std.mem.eql(u8, expected_em, em)) return error.Inconsistent;
            }
        };

        fn emsaEncode(hash: [Hash.digest_length]u8, out: []u8) ![]u8 {
            var temp_buf: [256]u8 = undefined;
            var encoder = DerEncoder{ .buffer = &temp_buf };
            
            const digest_info_result = try encoder.encodeDigestInfo(Hash, &hash);
            const digest_info_len = digest_info_result.len;
            
            const emLen = out.len;
            if (emLen < digest_info_len + 11) return error.ModulusTooShort;

            out[0] = 0x00;
            out[1] = 0x01;
            
            const padding_len = emLen - digest_info_len - 3;
            @memset(out[2..][0..padding_len], 0xff);
            
            out[2 + padding_len] = 0x00;
            
            @memcpy(out[3 + padding_len ..][0..digest_info_len], digest_info_result);

            return out[0..emLen];
        }
    };
}

const DerEncoder = struct {
    buffer: []u8,
    pos: usize = 0,

    pub const Error = error{
        BufferTooSmall,
        InvalidLength,
    };

    fn reset(self: *DerEncoder) void {
        self.pos = 0;
    }

    fn writeByte(self: *DerEncoder, byte: u8) Error!void {
        if (self.pos >= self.buffer.len) return error.BufferTooSmall;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    fn writeBytes(self: *DerEncoder, bytes: []const u8) Error!void {
        if (self.pos + bytes.len > self.buffer.len) return error.BufferTooSmall;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn encodeLength(self: *DerEncoder, len: usize) Error!void {
        if (len < 128) {
            try self.writeByte(@as(u8, @intCast(len)));
        } else {
            var len_bytes: [8]u8 = undefined;
            var len_size: usize = 0;
            var remaining = len;
            
            while (remaining > 0) : (len_size += 1) {
                len_bytes[len_size] = @as(u8, @intCast(remaining & 0xff));
                remaining >>= 8;
            }
            
            try self.writeByte(0x80 | @as(u8, @intCast(len_size)));
            
            var i: usize = len_size;
            while (i > 0) {
                i -= 1;
                try self.writeByte(len_bytes[i]);
            }
        }
    }

    fn encodeSequenceStart(self: *DerEncoder) Error!void {
        try self.writeByte(0x30);
    }

    fn encodeOid(self: *DerEncoder, oid: []const u8) Error!void {
        try self.writeByte(0x06);
        try self.encodeLength(oid.len);
        try self.writeBytes(oid);
    }

    fn encodeNull(self: *DerEncoder) Error!void {
        try self.writeByte(0x05);
        try self.writeByte(0x00);
    }

    fn encodeOctetString(self: *DerEncoder, bytes: []const u8) Error!void {
        try self.writeByte(0x04);
        try self.encodeLength(bytes.len);
        try self.writeBytes(bytes);
    }

    fn encodeDigestInfo(self: *DerEncoder, comptime Hash: type, hash: []const u8) Error![]const u8 {
        const start_pos = self.pos;
        
        var algo_id_buf: [32]u8 = undefined;
        var algo_encoder = DerEncoder{ .buffer = &algo_id_buf };
        
        const oid = getHashOid(Hash);
        try algo_encoder.encodeOid(oid);
        try algo_encoder.encodeNull();
        const algo_id_bytes = algo_id_buf[0..algo_encoder.pos];
        
        var algo_seq_buf: [64]u8 = undefined;
        var algo_seq_encoder = DerEncoder{ .buffer = &algo_seq_buf };
        try algo_seq_encoder.encodeSequenceStart();
        try algo_seq_encoder.encodeLength(algo_id_bytes.len);
        try algo_seq_encoder.writeBytes(algo_id_bytes);
        const algo_seq_bytes = algo_seq_buf[0..algo_seq_encoder.pos];
        
        const total_content_len = algo_seq_bytes.len + 2 + hash.len;
        
        try self.encodeSequenceStart();
        try self.encodeLength(total_content_len);
        try self.writeBytes(algo_seq_bytes);
        try self.encodeOctetString(hash);
        
        return self.buffer[start_pos..self.pos];
    }

    fn getHashOid(comptime Hash: type) []const u8 {
        const sha2 = std.crypto.hash.sha2;
        return switch (Hash) {
            std.crypto.hash.Sha1 => &[_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a },
            sha2.Sha224 => &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 },
            sha2.Sha256 => &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 },
            sha2.Sha384 => &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 },
            sha2.Sha512 => &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 },
            else => @compileError("unknown Hash " ++ @typeName(Hash)),
        };
    }
};

const ct = struct {
    fn lastIndexOfScalar(slice: []const u8, value: u8) ?usize {
        return std.mem.lastIndexOfScalar(u8, slice, value);
    }

    fn indexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
        return std.mem.indexOfScalarPos(u8, slice, start_index, value);
    }

    fn memEql(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }

    fn @"and"(a: bool, b: bool) bool {
        return a and b;
    }

    fn @"or"(a: bool, b: bool) bool {
        return a or b;
    }
};

const Parser = struct {
    bytes: []const u8,
    index: Index = 0,

    pub const Error = Element.Error || error{
        UnexpectedElement,
        InvalidIntegerEncoding,
        Overflow,
        NonCanonical,
        InvalidBool,
        UnknownObjectId,
    };

    pub fn expectBool(self: *Parser) Error!bool {
        const ele = try self.expect(.universal, false, .boolean);
        if (ele.slice.len() != 1) return error.InvalidBool;

        return switch (self.view(ele)[0]) {
            0x00 => false,
            0xff => true,
            else => error.InvalidBool,
        };
    }

    pub fn expectOid(self: *Parser) Error![]const u8 {
        const oid = try self.expect(.universal, false, .object_identifier);
        return self.view(oid);
    }

    pub fn expectEnum(self: *Parser, comptime Enum: type) Error!Enum {
        const oid = try self.expectOid();
        return Enum.oids.get(oid) orelse return error.UnknownObjectId;
    }

    pub fn expectInt(self: *Parser, comptime T: type) Error!T {
        const ele = try self.expectPrimitive(.integer);
        const bytes = self.view(ele);

        const info = @typeInfo(T);
        if (info != .int) @compileError(@typeName(T) ++ " is not an int type");
        const Shift = std.math.Log2Int(u8);

        var result: std.meta.Int(.unsigned, info.int.bits) = 0;
        for (bytes, 0..) |b, index| {
            const shifted = @shlWithOverflow(b, @as(Shift, @intCast(index * 8)));
            if (shifted[1] == 1) return error.Overflow;

            result |= shifted[0];
        }

        return @bitCast(result);
    }

    pub fn expectPrimitive(self: *Parser, tag: ?Identifier.Tag) Error!Element {
        var elem = try self.expect(.universal, false, tag);
        if (tag == .integer and elem.slice.len() > 0) {
            if (self.view(elem)[0] == 0) elem.slice.start += 1;
            if (elem.slice.len() > 0 and self.view(elem)[0] == 0) return error.InvalidIntegerEncoding;
        }
        return elem;
    }

    pub fn expectSequence(self: *Parser) Error!Element {
        return try self.expect(.universal, true, .sequence);
    }

    pub fn expectSequenceOf(self: *Parser) Error!Element {
        return try self.expect(.universal, true, .sequence_of);
    }

    pub fn expectEnd(self: *Parser, val: usize) Error!void {
        if (self.index != val) return error.NonCanonical;
    }

    pub fn expect(
        self: *Parser,
        class: ?Identifier.Class,
        constructed: ?bool,
        tag: ?Identifier.Tag,
    ) Error!Element {
        if (self.index >= self.bytes.len) return error.EndOfStream;

        const res = try Element.init(self.bytes, self.index);
        if (tag) |e| {
            if (res.identifier.tag != e) return error.UnexpectedElement;
        }
        if (constructed) |e| {
            if (res.identifier.constructed != e) return error.UnexpectedElement;
        }
        if (class) |e| {
            if (res.identifier.class != e) return error.UnexpectedElement;
        }
        self.index = if (res.identifier.constructed) res.slice.start else res.slice.end;
        return res;
    }

    pub fn view(self: Parser, elem: Element) []const u8 {
        return elem.slice.view(self.bytes);
    }

    pub fn seek(self: *Parser, index: usize) void {
        self.index = index;
    }

    pub fn eof(self: *Parser) bool {
        return self.index == self.bytes.len;
    }
};

const Element = struct {
    identifier: Identifier,
    slice: Slice,

    pub const Slice = struct {
        start: Index,
        end: Index,

        pub fn len(self: Slice) Index {
            return self.end - self.start;
        }

        pub fn view(self: Slice, bytes: []const u8) []const u8 {
            return bytes[self.start..self.end];
        }
    };

    pub const Error = error{ ReadFailed, EndOfStream, InvalidLength };

    pub fn init(bytes: []const u8, index: Index) Error!Element {
        var reader = Io.Reader.fixed(bytes[index..]);

        const identifier = @as(Identifier, @bitCast(try reader.takeByte()));
        const size_or_len_size = try reader.takeByte();

        var start = index + 2;
        if (size_or_len_size < 128) {
            const end = start + size_or_len_size;
            if (end > bytes.len) return error.InvalidLength;

            return .{ .identifier = identifier, .slice = .{ .start = start, .end = end } };
        }

        const len_size: u7 = @truncate(size_or_len_size);
        start += len_size;
        if (len_size > @sizeOf(Index)) return error.InvalidLength;
        const len = try reader.takeVarInt(Index, .big, len_size);
        if (len < 128) return error.InvalidLength;

        const end = std.math.add(Index, start, len) catch return error.InvalidLength;
        if (end > bytes.len) return error.InvalidLength;

        return .{ .identifier = identifier, .slice = .{ .start = start, .end = end } };
    }
};

const Identifier = packed struct(u8) {
    tag: Tag,
    constructed: bool,
    class: Class,

    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    pub const Tag = enum(u5) {
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        object_identifier = 6,
        real = 9,
        enumerated = 10,
        string_utf8 = 12,
        sequence = 16,
        sequence_of = 17,
        string_numeric = 18,
        string_printable = 19,
        string_teletex = 20,
        string_videotex = 21,
        string_ia5 = 22,
        utc_time = 23,
        generalized_time = 24,
        string_visible = 26,
        string_universal = 28,
        string_bmp = 30,
        _,
    };
};