import java.nio.ByteBuffer;
import java.lang.*;

public class SHA_512 {

byte[] bmes = new byte[128];
byte[] cipher = new byte[64];
byte[][] temp = new byte[80][8];
long word[] = new long[80];
byte[][] buff = new byte[8][8];
char[] cmes;
long s0,s1,S0,S1;
long[] H = { 0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
0xa54ff53a5f1d36f1L,
0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL,
0x5be0cd19137e2179L };
long[] k = { 0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
0xe9b5dba58189dbbcL, 0x3956c25bf348b538L,

0x59f111f1b605d019L, 0x923f82a4af194f9bL,

0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL,
0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL,
0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L,
0x76f988da831153b5L, 0x983e5152ee66dfabL,
0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL,
0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L,
0x81c2c92e47edaee6L, 0x92722c851482353bL,

14 | Page
0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L,
0xc76c51a30654be30L, 0xd192e819d6ef5218L,
0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L,
0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L,
0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L,
0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L,
0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
0xc67178f2e372532bL, 0xca273eceea26619cL,
0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L,
0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L,
0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L };

SHA_512(String message){
cmes = message.toCharArray();
//System.out.println(cmes.length);
for(int i =0;i&lt;cmes.length;i++) {
bmes[i] = (byte) cmes[i];
}
bmes[cmes.length] = (byte) 128;

bmes[127] = (byte) (8*cmes.length);
//System.out.print(bytesToHex(bmes));
word();
}

public void word() {
int k=0;
for(int i=0;i&lt;16;i++) {
for(int j=0;j&lt;temp[i].length;j++) {
temp[i][j] = bmes[k];
k++;
}

15 | Page

word[i] = BytesToLong(temp[i]);
}

for(int i=16;i&lt;80;i++) {
s0 = Long.rotateRight(word[i-15], 1)^Long.rotateRight(word[i-15],

8)^(word[i-15]&lt;&lt; 2);

s1 = Long.rotateRight(word[i-2], 19)^Long.rotateRight(word[i-2],

61)^(word[i-2]&lt;&lt; 6);

word[i] = word[i-16] + s0 + word[i-7] + s1;
}

apply_round();
}

public void apply_round() {
long a = H[0];
long b = H[1];
long c = H[2];
long d = H[3];
long e = H[4];
long f = H[5];
long g = H[6];
long h = H[7];

long ch,temp1,maj,temp2;
/*for i from 0 to 79

S1 := (e rightrotate 28) xor (e rightrotate 34) xor (e rightrotate 29)
ch := (e and f) xor ((not e) and g)
temp1 := h + S1 + ch + k[i] + w[i]
S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 29)
maj := (a and b) xor (a and c) xor (b and c)
temp2 := S0 + maj

h := g
g := f
f := e
e := d + temp1

16 | Page

d := c
c := b
b := a
a := temp1 + temp2*/

for(int i=0;i&lt;80;i++) {
S1 = Long.rotateRight(e,28) ^ Long.rotateRight(e,34) ^

Long.rotateRight(e,29);

ch = (e &amp; f)^((~e) &amp; g);
temp1 = h + S1 + ch + k[i] + word[i];
S0 = Long.rotateRight(a,28) ^ Long.rotateRight(a,34) ^

Long.rotateRight(a,29);

maj = (a &amp; b) ^ (a &amp; c) ^ (b &amp; c);
temp2 = S0 +maj;

h = g;
g = f;
f = e;
e = d + temp1;
d = c;
c = b;
b = a;
a = temp1 + temp2;
}

H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g;

H[7]+=h;

display();

}

private void display() {
byte[] b = new byte[8];
int l=0;
for(int i=0;i&lt;8;i++) {
b = LongtoBytes(H[i]);
for(int j=0; j&lt;8;j++,l++) {

17 | Page

cipher[l]=b[j];
//System.out.println(b[i]);
}
}

System.out.println(bytesToHex(cipher));

}

private final char[] HEX_ARRAY = &quot;0123456789ABCDEF&quot;.toCharArray();
public String bytesToHex(byte[] bytes) {
char[] hexChars = new char[bytes.length * 2];
for (int j = 0; j &lt; bytes.length; j++) {
int v = bytes[j] &amp; 0xFF;
hexChars[j * 2] = HEX_ARRAY[v &gt;&gt;&gt; 4];
hexChars[j * 2 + 1] = HEX_ARRAY[v &amp; 0x0F];
}
return new String(hexChars);
}

public long BytesToLong(byte[] longBytes){
ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
byteBuffer.put(longBytes);
byteBuffer.flip();
return byteBuffer.getLong();
}

public byte[] LongtoBytes(long data) {
return new byte[]{
(byte) ((data &gt;&gt; 56) &amp; 0xff),
(byte) ((data &gt;&gt; 48) &amp; 0xff),
(byte) ((data &gt;&gt; 40) &amp; 0xff),
(byte) ((data &gt;&gt; 32) &amp; 0xff),
(byte) ((data &gt;&gt; 24) &amp; 0xff),
(byte) ((data &gt;&gt; 16) &amp; 0xff),
(byte) ((data &gt;&gt; 8) &amp; 0xff),
(byte) ((data &gt;&gt; 0) &amp; 0xff),

18 | Page

};
}

}
import java.util.*;
public class Encrypt {

public static void main(String[] args) {
Scanner sc = new Scanner(System.in);
System.out.print(&quot;Enter the message : &quot;);
String message = sc.nextLine();

SHA_512 sha = new SHA_512(message);
}

}