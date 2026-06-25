/* Host-side X.509 / PKI tests. v1 covers the ASN.1 DER reader (x509/asn1.c):
 * synthetic TLVs for every accept/reject path, plus a structural walk of the
 * real RFC 8448 server certificate (a genuine DER blob). Build/run:
 * `make x509-test`. No QEMU, no networking. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "asn1.h"
#include "x509.h"
#include "verify_cert.h"

/* The 432-byte DER certificate from RFC 8448 §3 (extracted verbatim). */
#define RFC_DER_CERT "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1"

/* A synthetic minimal certificate carrying a SubjectAltName with two dNSName
 * entries (RFC 8448's cert has none). Built by tools (correct DER lengths). */
#define SAN_CERT "3081ca3081b1a003020102020101300d06092a864886f70d01010b050030123110300e0603550403130754657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d301f300d06092a864886f70d0101010500030e00300b020400c0ffee0203010001a32b302930270603551d110420301e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d300d06092a864886f70d01010b0500030500deadbeef"

/* A real ECDSA P-256 / ecdsa-with-SHA256 self-signed certificate, CN/SAN =
 * aurora-ec-test (test/tls/ec_cert.pem). Generated with:
 *   openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem
 *   openssl req -x509 -new -key ec_key.pem -sha256 -days 3650 \
 *       -subj "/CN=aurora-ec-test" -addext "subjectAltName=DNS:aurora-ec-test" \
 *       -out ec_cert.pem
 * This is the analogue of RFC_DER_CERT for the ECDSA verification path. */
#define EC_CERT "308201a230820148a003020102021475f0594af486a3924c0107c26e17f37afff12fb7300a06082a8648ce3d04030230193117301506035504030c0e6175726f72612d65632d74657374301e170d3236303632343037353834355a170d3336303632313037353834355a30193117301506035504030c0e6175726f72612d65632d746573743059301306072a8648ce3d020106082a8648ce3d0301070342000495982cd8b24b904afc1a61e9ebb41c858b3f7ebe2f237133a0e28e23f67af4501d856285231af5fe01da4df2da8757b4c037be0bce75c1e7ec4f6f6ed76d1a31a36e306c301d0603551d0e04160414504dc74f919284b4687854efb57f3c251615bea4301f0603551d23041830168014504dc74f919284b4687854efb57f3c251615bea4300f0603551d130101ff040530030101ff30190603551d1104123010820e6175726f72612d65632d74657374300a06082a8648ce3d04030203480030450221009a1c56dbedf726b01bcfbb03b67fadc567c88c643a50aa5670fac6d554a8576c02201790e03885d6bdb1eb6f01a266a75bbff57c62d740c20842971d8c61d962d460"

/* A real ECDSA P-256 PKI for depth-N path building (14.0.1), from openssl:
 *   PKI_ROOT  (self-signed, CA:TRUE + keyCertSign)
 *   PKI_INTER (signed by root, CA:TRUE + keyCertSign)
 *   PKI_LEAF  (signed by inter, CA:FALSE, SAN aurora-leaf.test)
 * plus adversarial variants that must be REJECTED:
 *   PKI_INTER_NOTCA  (CA:FALSE but keyCertSign) + PKI_LEAF_B signed by it
 *   PKI_INTER_NOKUCS (CA:TRUE but no keyCertSign) + PKI_LEAF_C signed by it
 * All valid 2024-01-01..2034-01-01. */
#define PKI_ROOT "308201953082013da00302010202144c3bbe68398996e7acaa725699d43cf0b31a377a300a06082a8648ce3d04030230193117301506035504030c0e4175726f726120526f6f74204341301e170d3236303632343130333732335a170d3336303632313130333732335a30193117301506035504030c0e4175726f726120526f6f742043413059301306072a8648ce3d020106082a8648ce3d03010703420004c46549472e5674894eadafd0a188f8e6d39b2458cfe28a47faf333640cc05e16c347b211d13bb98a23c0e9a8337416ac08c7b77783b33d6df8915f62b32df903a3633061301d0603551d0e04160414ae6db9cf67b96411ecf598b33b87b5f32d2f47d7301f0603551d23041830168014ae6db9cf67b96411ecf598b33b87b5f32d2f47d7300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020346003043021f10a532437b7fd53719fc880d0dd0a92c5a2be8fdbbb2309e1e96995cb835230220736ecbb851c253c54094705130a7c633cb3d80ad447febad6e63ba9d040d030b"
#define PKI_INTER "308201a030820145a00302010202142766ff78a0e91a5cff4fb67a448784ff86728b47300a06082a8648ce3d04030230193117301506035504030c0e4175726f726120526f6f74204341301e170d3236303632343130333732335a170d3336303632313130333732335a3021311f301d06035504030c164175726f726120496e7465726d6564696174652043413059301306072a8648ce3d020106082a8648ce3d030107034200041eedf17d31f8f1feb31d0812a778e81e105fa1da2900c729227bd61db262ef89b1cb49023d795f152167d03412157dc3cc62dcbd4f61389e8a4f7cdd0d916548a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414f69e954994ab568f9b39ff7475965646de9be986301f0603551d23041830168014ae6db9cf67b96411ecf598b33b87b5f32d2f47d7300a06082a8648ce3d0403020349003046022100a568c1319fc2f57e87c4b5f072a29e1b26db28e3d761cb81fb189264bca91b19022100cf46cc95b2b3d9a82b3bc8822e83e5c04e6055ac23bfe02abbb5a4b8314673bc"
#define PKI_LEAF "308201b83082015ea0030201020214498150f0b3e2917e31d300d80329ae08d6f8b79e300a06082a8648ce3d0403023021311f301d06035504030c164175726f726120496e7465726d656469617465204341301e170d3236303632343130333732335a170d3336303632313130333732335a301b3119301706035504030c106175726f72612d6c6561662e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004f7de4f07b4f3078145be863e8dd3ab6d53563bcadaa43a5c21b9f2b9672da16512f6432dc62f1975eef28789b0cad76e9ba9e28244e1718f3e04d97111bd895aa37a307830090603551d1304023000300e0603551d0f0101ff040403020780301b0603551d110414301282106175726f72612d6c6561662e74657374301d0603551d0e04160414c7bdf72640996fdb2c118f432017ed6c4abc7ca1301f0603551d23041830168014f69e954994ab568f9b39ff7475965646de9be986300a06082a8648ce3d040302034800304502210085e38fedf083427bf080f1e3b8e5430b6f43d0bb2c62885a0811f15f81ba8bca022077479001e3c199278e06aad27eb845829002ea039a955ac53e15b8e83b27adf2"
#define PKI_INTER_NOTCA "308201993082013ea00302010202142766ff78a0e91a5cff4fb67a448784ff86728b48300a06082a8648ce3d04030230193117301506035504030c0e4175726f726120526f6f74204341301e170d3236303632343130333732335a170d3336303632313130333732335a301d311b301906035504030c124175726f7261204e6f74434120496e7465723059301306072a8648ce3d020106082a8648ce3d030107034200047550660de844754702e76136813f54f6f1c7c239e8f3281572157cf0d722091b1e296b3b47101b0eb941c1e72d9fdcf0d9a79847e4f7b5a4f8b6babd65af5602a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020106301d0603551d0e04160414d8894bcb6cadfee92638a17c2bcf5826d897ca65301f0603551d23041830168014ae6db9cf67b96411ecf598b33b87b5f32d2f47d7300a06082a8648ce3d0403020349003046022100ac6f1dbdb8e37c4e0fb4aafbb73f0569fe76e04ea363cabf04eab6d53b6d07bf022100f1d469519f1dc74defdd1b2145218b81a74b33410ceb20938e4383634a704f78"
#define PKI_LEAF_B "308201b93082015ea003020102021477c48a4eade8b67f744249e05f54e144f08ccebc300a06082a8648ce3d040302301d311b301906035504030c124175726f7261204e6f74434120496e746572301e170d3236303632343130333732335a170d3336303632313130333732335a301d311b301906035504030c126175726f72612d6c6561662d622e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004efc467b696e78bfc04178c1a9db6a5c63033d1179aa683a07e6d2ca848e25db55063bb5638f2214b68f91aed95cc2d1467ce389ece73672da942d3d69cdf199da37c307a30090603551d1304023000300e0603551d0f0101ff040403020780301d0603551d110416301482126175726f72612d6c6561662d622e74657374301d0603551d0e04160414fac98472081a0406e60bbfc2985232773ed55b53301f0603551d23041830168014d8894bcb6cadfee92638a17c2bcf5826d897ca65300a06082a8648ce3d0403020349003046022100f8dba210d24b808496313574cc516754ddda0f5caa21b67cb60df250a374924302210082a5a167071fab8b6d4774773ea9ca15a046da8603729496cd31707d6074e7c7"
#define PKI_INTER_NOKUCS "3082019b30820142a00302010202142766ff78a0e91a5cff4fb67a448784ff86728b49300a06082a8648ce3d04030230193117301506035504030c0e4175726f726120526f6f74204341301e170d3236303632343130333732335a170d3336303632313130333732335a301e311c301a06035504030c134175726f7261204e6f4b55435320496e7465723059301306072a8648ce3d020106082a8648ce3d03010703420004ba6e6fa7a84a7baefee30575d4a8727f5077f16485b4213df93ec79c66a1fe2c03c4bc1d80d7423aa54b163b3f8f0e9914c73dfbaa2ee8267340ce5ff4668ac9a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020780301d0603551d0e0416041463b0708744d56dea9135463f93b7d69895baed80301f0603551d23041830168014ae6db9cf67b96411ecf598b33b87b5f32d2f47d7300a06082a8648ce3d040302034700304402203a1a03a3989bf164986349a216ed58d0eb34d40f234a39297c3c233e8e9237b502206afd79aa9d0004f714335fe8e8538d5c5138f73b230ccd0e2270e0f38525523c"
#define PKI_LEAF_C "308201ba3082015fa00302010202144271906a21fd299de35cccf0440e0ecf3934b6b1300a06082a8648ce3d040302301e311c301a06035504030c134175726f7261204e6f4b55435320496e746572301e170d3236303632343130333732335a170d3336303632313130333732335a301d311b301906035504030c126175726f72612d6c6561662d632e746573743059301306072a8648ce3d020106082a8648ce3d0301070342000443c7603297eb3a7d8452b5dfa5b90d7c4c43182c7b0a3e76e21f0869e9da55f85cfd5b13c82e3f8ba69033296af5916a5d1b44d9ec1b97127deceb158cd47300a37c307a30090603551d1304023000300e0603551d0f0101ff040403020780301d0603551d110416301482126175726f72612d6c6561662d632e74657374301d0603551d0e0416041406800a4b81524a7d39b6af6d4cce8f8ce97bc140301f0603551d2304183016801463b0708744d56dea9135463f93b7d69895baed80300a06082a8648ce3d0403020349003046022100dcaf8e8b5df68deb29f6a1cbc1fb846d03cc529516e329deb2191f09dd1ef748022100f582ed54cc8ba480fe95bc2b3ea2f7f75b16ee77ef70c38131a9b2caf2f98fd6"

/* A P-384 chain (openssl-generated, all ecdsa-with-SHA384 / secp384r1) for the
 * 14.x.4 X.509 dispatch: root (CA) -> intermediate (CA, pathlen 0) -> leaf
 * (p384.aurora.test). Exercises OID_P384 key classification and the
 * ecdsa-with-SHA384 signature path through x509_verify_chain. */
#define PKI384_ROOT "308201d83082015ea003020102021436e8de5a97ab62d457731d89b59781623c4f2bd5300a06082a8648ce3d040303301b3119301706035504030c104175726f7261205033383420526f6f74301e170d3236303632353130343432365a170d3336303632323130343432365a301b3119301706035504030c104175726f7261205033383420526f6f743076301006072a8648ce3d020106052b81040022036200044d09f321dc09000b6e8b56df0861e0d1a25bdcc8123634c40553e0910aafeac398543397ad6b9110a0e31c71b28a02fd27ca8c5f25914b6a908611cc1449f66a6f2a5e92e7374390ef321c9c4069f4daa52abe48f66547fbf8bb2cfcffac838ca3633061301d0603551d0e04160414ef006a819eabf91e371b9b7e3310eaa3e4cfe715301f0603551d23041830168014ef006a819eabf91e371b9b7e3310eaa3e4cfe715300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030368003065023019b8f8aef372e347764128978d2ed1f10b415e3250aebbec706faeb2ddf0d88d6e0a623436642562861db89790a885320231009f103dc42b5070d4ea3df4e1905140f367f6e95b72fe126d20fb3d7916c9fb79c8c12e18e536d34756e01dc586b3bbc9"
#define PKI384_INTER "308201e230820169a00302010202143d4eb0232e7e890f4257c19c5a0f5658886fefe1300a06082a8648ce3d040303301b3119301706035504030c104175726f7261205033383420526f6f74301e170d3236303632353130343432365a170d3336303632323130343432365a30233121301f06035504030c184175726f7261205033383420496e7465726d6564696174653076301006072a8648ce3d020106052b81040022036200041c9720aeaa8f193b60b1826059e2e8356856c8ca2621f33cdaadcdedfb9b4e5f6ce3e028fb4b6b941486e86e87524cd0be9e613d4b5fe9ef7f3319770a49874730ea2dd14df8f574f6480bbbfc0df3b6cb02022e1f59a960aa65a50db4efc3fba366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106301d0603551d0e04160414993e08132eb535189e4684a46f4c0a66560b6757301f0603551d23041830168014ef006a819eabf91e371b9b7e3310eaa3e4cfe715300a06082a8648ce3d040303036700306402300d5577d3e24e4d1db05153e930b0fd20cd5d907ac1656db9988fc8b6cbe20cd6d30ede7c27fc6a3058d9c547864c6a71023063aed2c665a62f7312f27529a09614497f6bb28095568fb3279e87a5172038e016c84e49fd036e6cc378eb9aaf3326d6"
#define PKI384_LEAF "308201fa30820180a0030201020214442a7c6186dd072787a0ffc01997e337854869e8300a06082a8648ce3d04030330233121301f06035504030c184175726f7261205033383420496e7465726d656469617465301e170d3236303632353130343432365a170d3336303632323130343432365a301b3119301706035504030c10703338342e6175726f72612e746573743076301006072a8648ce3d020106052b81040022036200048893c789bbda82f1161862bdc429255132e8335dc7a9ddcdbc5e0c89450d1d67d273ec3be71a235f369380bb92751d0acb4b0beeaedee690dfd8a283b2626bcf3f683c6cb584074353d6edbec33973fe5df9494165cc133c9552c975cc31d663a37d307b300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301b0603551d11041430128210703338342e6175726f72612e74657374301d0603551d0e04160414cda30d2fa29cb669b03e89fbd27887a4431f7064301f0603551d23041830168014993e08132eb535189e4684a46f4c0a66560b6757300a06082a8648ce3d0403030368003065023025239ef748094bb025075a8d0889519024d467fbfc9590e9d4822b716b82a22274a8853bc44b784659815a9461397b66023100bcfd7f733e64a6b04657062ceaf51a2832716f35f67ee76983dd0132c916d9bbee63fe29e6da452f0c4a4212a2183b78"

/* A REAL captured Let's Encrypt chain (www.eff.org, June 2026) for offline
 * validation (14.0.2). All RSA-PKCS1-SHA256, which Aurora can verify:
 *   PKI_LE_LEAF   (*.eff.org, RSA-2048) -> PKI_LE_YR1 (LE "YR1", RSA-2048)
 *   -> PKI_LE_ROOTYR ("Root YR", RSA-4096) -> PKI_ISRG_X1 (ISRG Root X1, RSA-4096)
 * The leaf + two intermediates are what the server sends; ISRG Root X1 is the
 * trust anchor. It really chains to the published ISRG Root X1 (openssl-verified),
 * so this proves depth-3 path building + RSA verification on genuine bytes. */
#define PKI_LE_LEAF "308204fe308203e6a003020102021205847e27145decfbdb15ea01804b977a1fd9300d06092a864886f70d01010b05003033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231301e170d3236303632323039353333375a170d3236303932303039353333365a30143112301006035504030c092a2e6566662e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100d7455be3a0d89573ce2c48a80b80647f14ead14a31661b374a1a253ac6b7e5d69d8f0cec5e30461f0600e9b71c94c5508effcce17e3b4eff215305557591086d07c7050459871d587952bc685faa4b164add0ac4139b98da45a80d4796aa36016e600348187fe7a6d6ca7533d7f336536c04489c0add9b860d5ed3ed4d755e736e9daac2f98d802d948a5633ccf82aa2ebe1895af984dc2ebb483b06b67fcc427060f3d14b568e71993e3d7a84ff38bb567924845eede82d395bb1ad654d3c424d3fee86ccaf014bcb2a4fb1f7a16a6f3afc5ee86305d6182571b85264fce6543fb79dcedc35ddfe8cf826ce1b8496d84b4fae85f1412f024fd7c02a37266ed50203010001a382022930820225300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e04160414dd119c8bc1e04e80d0ae5bc7183eb721951bf350301f0603551d230418301680141f2f35be461482cd40b1ae792c5578faf7d468fb303306082b0601050507010104273025302306082b060105050730028617687474703a2f2f7972312e692e6c656e63722e6f72672f30270603551d110420301e82092a2e6566662e6f726782112a2e73746167696e672e6566662e6f726730130603551d20040c300a3008060667810c010201302e0603551d1f042730253023a021a01f861d687474703a2f2f7972312e632e6c656e63722e6f72672f39302e63726c3082010b060a2b06010401d6790204020481fc0481f900f7007600c8a3c47fc7b3adb9356b013f6a7a126de33a4e43a5c646f997ad3975991dcf9a0000019eeef581d5000004030047304502203e338d3fb59b6baf2e68f8406ac595ee8818b44ea7171a858a218fbfc6ff0c9d022100d73edc7048e62dc79453da9556bb78ff33047992df32f047498c368ab22bf601007d0026e3646e58692123bc343f4724359b3792cd245a88d815d39333fd9918ab47230000019eeef580a800080000050020d5a008040300463044022037fa3966adb56e295d6c9ab45fc7175f7ac9bc6dbe5a17cb5d6c89f1f9fdaf3002204e8ef100f29f778114d61e8abfbf6f6013facd31b43e6b8490539fc8b4743cc0300d06092a864886f70d01010b0500038201010023eb4498a9e2f4401bc6f2cd3dedd284ce67946efcf279747d72181d18c01367af2c9cb3c1d6fdee8100a8c446853e33405940e15d32f71a69b91868c50dde435dee6bd3af3f676192bb488e06d2df637131d9e6378ea4ac69d593db66240a74aac756f1555851b652ed6bdf3c7c8bc12d61489437f1efd9802148882d7d3bada756bcfee36ea4c5f91eb0a0f0f6d038d65ea4620e7c39f0191f6958fa1e9c009fa61bcd557562256d37b92cc99ae38f3f4e8fbefa765e5b4956c9e60b345c880ad3980b634a6d3020aeebc436ca22ababdc199660df326f55f40d87d2d9c9c6fb677f2bd46a76c3abdf898ee068e1e77377f26fb31d20e43b74838bc631f0e1"
#define PKI_LE_YR1 "308204db308202c3a003020102021100a20253f15f2691c05dc1ce13b9bcca4e300d06092a864886f70d01010b0500302e310b3009060355040613025553310d300b060355040a1304495352473110300e06035504031307526f6f74205952301e170d3235303930333030303030305a170d3238303930323233353935395a3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a0603550403130359523130820122300d06092a864886f70d01010105000382010f003082010a0282010100a158bc5f6c42620317bc9c4d3caa7fa05d7750c8263c0041d3b5422cd0eda179adf65b8464d252055d745724f53f3e8b0fc66ad5dda0738dd6365d40751ae3e2c1276b36ce8b3d273e9986069da1ba2e3da19b43218eb074a799022e416cd536d021fa45204130b490f5c5eb1fc77176fe0f009e39b2c18c2faf14484dc1b230b66ba70037d2f90a05d52108b9b5f3624cfa05659dd2d0e957a8b9a6b5d57de6e75601be5be9efc5e3d0e20ac1f4634d0083bd815486f5873ca798a7be5f49844414edb1bdc1c26a55f62a5e06330ba11fc3f5c1f11d0096a22e654e65f0634d79279ac67a5cf59d98c9bb1736922a1a5f6f572419e13243f9df5ad2746e6e330203010001a381ee3081eb300e0603551d0f0101ff04040302018630130603551d25040c300a06082b0601050507030130120603551d130101ff040830060101ff020100301d0603551d0e041604141f2f35be461482cd40b1ae792c5578faf7d468fb301f0603551d23041830168014dee75b60d0226d40287d3f0d01fea4b552b45194303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f79722e692e6c656e63722e6f72672f30130603551d20040c300a3008060667810c01020130270603551d1f0420301e301ca01aa0188616687474703a2f2f79722e632e6c656e63722e6f72672f300d06092a864886f70d01010b05000382020100d3ecef32ade41e283575d4e69a6f9189b4ebf7f4695fb9386ee6a730c46a6d5ff222f3fcdb30073779af6b0f9c012b95b1da5dd2292386be219e12502d03b33a9d9c70aaec746380828d2f75d78848502a116115e25994337bc517bf7aba9f9b4a0989d6ee91ba90c23310e017c33778bbc6ba3e8bd25bb7ce44342ae40b9cac4bb41d2842a9f521d8390aeb86a4cbd0ce4dbd3dadc3fea1eeadcd0420cf52c6e910b89aaaeb7971b18c9140553cc8c04e86ad70e4b6df696351af3d6e92539f23fa589006f613631366b00c4240481364bc26dd45f2045cf7aa3fc4eb2b82f4a46bce008ac5fac6ad65cf567b8c6beb9d77384cc723c594e38936a285c608d492176622ed10c4826b997772ef1859deb374b45096a45d725563b907cd1dac1127a1969642b4409a2c8af4cac1d070dcac44b731a8f323071116eccb9ee03f55171ce31c9996100b482dc91dd2c5f7a720cfccc42dc86b662969bfe443f0939e5227d8a4392540ba358ac609b84537d6e9e652894ad1300949cba67b5cad79395d50c236fff94725a945386418e57b19eb4a910d2a018f210b358aea8aa70210d972395855d59fa8ec370c8397e840cd06002a1daad1571c85f5065d39a5d2c8f274b9e0f6058244060682190f2b01a53f41cd76dd5e4b4d70d95b809cb0f043ca1cb8bfe73c842940cb0fc890995f06ac41f43fbfc2f20c1e0102678a6d3faa"
#define PKI_LE_ROOTYR "308205f4308203dca003020102021100f24b6d17f9d9ad7cb1c9fea78782699f300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3236303531333030303030305a170d3332303930323233353935395a302e310b3009060355040613025553310d300b060355040a1304495352473110300e06035504031307526f6f7420595230820222300d06092a864886f70d01010105000382020f003082020a0282020100dbc626737bf024c97562f7f9e19fb0b3794eb34126cf951fd8515ea45bc31bbdb06362074043d5f70ec5b494402248335c44d770dbfb90b0d70d2cd04058b2fb883ffea3a05d30f1cb8899b811d4e1a061b490e0ea7323e0c6f121ae4e5704f3bdce092fa4877b2b968eaf978dcce4e260e007a8d6c7c7a7a913243a0888504d24063e38a7d7fc552f60aba18d3fa7a38f659aa9aea52048e4f901422aab106b56539bb153f7105871aef234a3141ce766abdb34f2cc5cc2c5c426f75937eb2415d78eabd61bebf86e3cf18e3780b4e954eea6ab443bcd3b202e4182e59fdd3833e7da2b1f219cb0a9275e59a9a12070d958fbd30c59c0b9caf2f60368f797dfb66ee820657f9d384f75cd898875ac13bd266e56f95b46b0252f1201ea9c0c0639de5c28d843cfb70420a3b2c6d2369654de14dc0437617c09440e562bea911ab6731d9834f906a9ca0bdd9b7741213357db2c78a82dc70b0ae89ebd3f1990f859aeaecc8a2ee035701c504011f3e97361a97ef734e0ec2e4300bc9539e1bf0aa7d100c9f52921c247435203a3fcb67fe619196709cb79aed5422e7572495a54e87d6a1a0dc38133aeb247fc79a85332261b2397b33c998ee5eaed6a5b24435bada7be3e783cbdd8f2387ed1ca4dbabd216847e1864a8775a724422dfa842f95865b63cb6912ba0aac507a3c51b3ac9203472b6ce07aafb87e764458f6ceffc10203010001a381eb3081e8300e0603551d0f0101ff04040302010630130603551d25040c300a06082b06010505070301300f0603551d130101ff040530030101ff301d0603551d0e04160414dee75b60d0226d40287d3f0d01fea4b552b45194301f0603551d2304183016801479b459e67bb6e5e40173800888c81a58f6e99b6e303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f78312e692e6c656e63722e6f72672f30130603551d20040c300a3008060667810c01020130270603551d1f0420301e301ca01aa0188616687474703a2f2f78312e632e6c656e63722e6f72672f300d06092a864886f70d01010b050003820201003cb29488f7928a7e7d96e863260e91c12523da2dbb12dd6f777228c909109801cd5fb0980bd4520bec2d02f5e70f39d7300767e2d03936a7de23f624c90b19ade4215228b456c275d3d8c3125dec55c6aa1507bf417563f155711391599efea61202e2951e1e4fb3ee418b1826c12d4992348073e31fad46cdb2c5441271f468488087eae8b570152523ff61eecb24f1300fd0d61bbdaf5566e101cb8e7f938b8f3e7b0ad93b320407ca767bf8f94726d6a3ae809a21bb42afab5c659680c14426fa3432796755fb686ff5d78e60598a790ca38dc4ab37935a76bc3e2fd0d924b6c0d47a9e36f2e1060aa93f47ef26ad8de84b43e7be0de9e308eee32c2539e38b6503cfd7a5e572d2bfd7ea24cb8342d6156f6a133682a9a14aa1c4f542d1aab8786e4c112688767f1be5919249e0092cc1d796311d94dcdafa771f92f8979353ce2e79c576fc7cfe093a337ef859b2d6157c3c375e3507f465fed20d19f9754f13888aab6231890bd3645219bd64ab7e012fd34f3f6ef344632e1c69f34b784522b4537cac6bcd467d473416cc41b72ba7c9debda7a9296d91ecad8acf43201a0563d5665728cb33bd43322fb2d7e4d1489542944330bc0e322fefbbabd5d9c79af9c014560789104ca1f9ab2a199c3c3b8a2ba1d65203c83171f2bee2f6f2095391d2de6a192e461600e8a531a57d379e80f4181be9d35c1e4be0dcda1a60"
#define PKI_ISRG_X1 "3082056b30820353a0030201020211008210cfb0d240e3594463e0bb63828b00300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3135303630343131303433385a170d3335303630343131303433385a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b05000382020100551f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d321977ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea912b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b573a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b52ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355ca328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdca2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073fb9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade1827"

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

static int unhex(const char *s, uint8_t *out)
{
    int n = 0;
    for (; s[0] && s[1]; s += 2) {
        int hi = s[0] <= '9' ? s[0]-'0' : (s[0]|32)-'a'+10;
        int lo = s[1] <= '9' ? s[1]-'0' : (s[1]|32)-'a'+10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* parse a single TLV from a byte literal; return the asn1_next result */
static int parse1(const uint8_t *buf, size_t len, asn1_tlv *t)
{
    asn1_cursor c; asn1_cursor_init(&c, buf, len);
    return asn1_next(&c, t);
}

/* SAN entries are now (ptr,len) views into the DER, not NUL-terminated copies. */
static int san_is(const x509_cert *cert, int i, const char *s)
{
    size_t n = strlen(s);
    return i < cert->san_count && cert->san_dns[i].len == n &&
           memcmp(cert->san_dns[i].p, s, n) == 0;
}

int main(void)
{
    printf("ASN.1 DER reader — TLV basics:\n");
    {
        asn1_tlv t;
        uint8_t i5[]  = { 0x02, 0x01, 0x05 };               /* INTEGER 5 */
        check_ok("INTEGER parses (tag/len)", parse1(i5, sizeof i5, &t) == 0 && t.tag == ASN1_INTEGER && t.len == 1);
        uint64_t v = 0;
        check_ok("INTEGER value == 5", asn1_get_uint(&t, &v) == 0 && v == 5);

        uint8_t os[] = { 0x04, 0x03, 0xaa, 0xbb, 0xcc };    /* OCTET STRING */
        check_ok("OCTET STRING len == 3", parse1(os, sizeof os, &t) == 0 && t.tag == ASN1_OCTET_STRING && t.len == 3);

        /* long-form length: 0x81 0x80 => 128 content octets */
        uint8_t lf[131]; lf[0] = 0x04; lf[1] = 0x81; lf[2] = 0x80;
        for (int i = 0; i < 128; i++) lf[3 + i] = (uint8_t)i;
        check_ok("long-form length == 128", parse1(lf, sizeof lf, &t) == 0 && t.len == 128 && t.value[127] == 127);

        /* SEQUENCE { INTEGER 1, INTEGER 2 } — open and iterate */
        uint8_t seq[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        asn1_cursor c; asn1_cursor_init(&c, seq, sizeof seq);
        asn1_cursor in;
        check_ok("SEQUENCE opens", asn1_open(&c, ASN1_SEQUENCE, &in) == 0);
        asn1_tlv a, b; uint64_t va = 0, vb = 0;
        int ok = asn1_next(&in, &a) == 0 && asn1_get_uint(&a, &va) == 0
              && asn1_next(&in, &b) == 0 && asn1_get_uint(&b, &vb) == 0;
        check_ok("two INTEGERs 1,2 in order", ok && va == 1 && vb == 2);
        check_ok("inner cursor fully consumed", asn1_cursor_empty(&in));
        check_ok("outer cursor fully consumed", asn1_cursor_empty(&c));

        uint8_t tag = 0;
        asn1_cursor_init(&c, seq, sizeof seq);
        check_ok("peek does not consume", asn1_peek_tag(&c, &tag) == 0 && tag == ASN1_SEQUENCE && c.p == seq);
    }

    printf("ASN.1 DER reader — rejects malformed input:\n");
    {
        asn1_tlv t;
        check_ok("empty buffer -> -1", parse1((const uint8_t*)"", 0, &t) == -1);
        uint8_t no_len[]  = { 0x02 };
        check_ok("missing length octet -> -1", parse1(no_len, sizeof no_len, &t) == -1);
        uint8_t over[]    = { 0x04, 0x05, 0xaa, 0xbb };     /* claims 5, has 2 */
        check_ok("length exceeds buffer -> -1", parse1(over, sizeof over, &t) == -1);
        uint8_t indef[]   = { 0x30, 0x80, 0x00, 0x00 };     /* indefinite length */
        check_ok("indefinite length -> -1", parse1(indef, sizeof indef, &t) == -1);
        uint8_t nonmin[]  = { 0x02, 0x81, 0x01, 0x05 };     /* long form for len 1 */
        check_ok("non-minimal long form -> -1", parse1(nonmin, sizeof nonmin, &t) == -1);
        uint8_t leadzero[] = { 0x02, 0x82, 0x00, 0x80 };    /* leading zero length octet */
        check_ok("leading-zero length octet -> -1", parse1(leadzero, sizeof leadzero, &t) == -1);
        uint8_t hightag[] = { 0x1f, 0x20, 0x01, 0x00 };     /* high-tag-number form */
        check_ok("high-tag-number form -> -1", parse1(hightag, sizeof hightag, &t) == -1);
        uint8_t lenoflen[] = { 0x04, 0x85, 0x01,0x02,0x03,0x04,0x05 }; /* 5 length octets */
        check_ok("oversized length-of-length -> -1", parse1(lenoflen, sizeof lenoflen, &t) == -1);

        uint8_t neg[] = { 0x02, 0x01, 0xff };               /* INTEGER, high bit set */
        check_ok("INTEGER parses but get_uint rejects negative", parse1(neg, sizeof neg, &t) == 0 && asn1_get_uint(&t, (uint64_t[]){0}) == -1);
        uint8_t nmi[] = { 0x02, 0x02, 0x00, 0x05 };         /* non-minimal INTEGER */
        check_ok("non-minimal INTEGER -> get_uint -1", parse1(nmi, sizeof nmi, &t) == 0 && asn1_get_uint(&t, (uint64_t[]){0}) == -1);

        /* expect() restores the cursor on a tag mismatch */
        asn1_cursor c; asn1_cursor_init(&c, neg, sizeof neg);
        check_ok("expect(wrong tag) -> -1 and cursor unchanged",
                 asn1_expect(&c, ASN1_SEQUENCE, &t) == -1 && c.p == neg);
    }

    printf("ASN.1 DER reader — RFC 8448 server certificate (real DER):\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        check_ok("DER blob is 432 bytes", derlen == 432);

        /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
        asn1_cursor c; asn1_cursor_init(&c, der, derlen);
        asn1_cursor cert;
        check_ok("Certificate SEQUENCE opens", asn1_open(&c, ASN1_SEQUENCE, &cert) == 0);
        check_ok("nothing trails the outer SEQUENCE", asn1_cursor_empty(&c));

        asn1_tlv tbs, sigalg, sig;
        int top = asn1_expect(&cert, ASN1_SEQUENCE, &tbs) == 0      /* tbsCertificate */
               && asn1_expect(&cert, ASN1_SEQUENCE, &sigalg) == 0   /* signatureAlgorithm */
               && asn1_expect(&cert, ASN1_BIT_STRING, &sig) == 0;   /* signatureValue */
        check_ok("three top-level fields parse", top);
        check_ok("Certificate fully consumed", asn1_cursor_empty(&cert));
        check_ok("tbsCertificate length == 277", tbs.len == 277);
        check_ok("signatureValue is a BIT STRING", sig.tag == ASN1_BIT_STRING);

        /* descend into tbsCertificate */
        asn1_cursor tc; asn1_cursor_init(&tc, tbs.value, tbs.len);

        /* [0] EXPLICIT version => INTEGER 2 (v3) */
        asn1_cursor ver;
        uint8_t vt = 0;
        check_ok("version is context [0] (0xA0)", asn1_peek_tag(&tc, &vt) == 0 && vt == (ASN1_CONTEXT|ASN1_CONSTRUCTED|0));
        asn1_tlv vint; uint64_t version = 99;
        int vok = asn1_open(&tc, ASN1_CONTEXT|ASN1_CONSTRUCTED|0, &ver) == 0
               && asn1_next(&ver, &vint) == 0 && asn1_get_uint(&vint, &version) == 0;
        check_ok("version == 2 (v3)", vok && version == 2);

        /* serialNumber INTEGER == 2 */
        asn1_tlv serial; uint64_t sn = 99;
        check_ok("serialNumber == 2", asn1_expect(&tc, ASN1_INTEGER, &serial) == 0
                 && asn1_get_uint(&serial, &sn) == 0 && sn == 2);

        /* signature AlgorithmIdentifier => OID sha256WithRSAEncryption */
        static const uint8_t oid_sha256rsa[] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
        asn1_cursor alg; asn1_tlv algoid;
        int aok = asn1_open(&tc, ASN1_SEQUENCE, &alg) == 0 && asn1_next(&alg, &algoid) == 0;
        check_ok("signature algorithm == sha256WithRSAEncryption",
                 aok && asn1_oid_equals(&algoid, oid_sha256rsa, sizeof oid_sha256rsa));

        /* issuer SEQUENCE (skip), then validity { UTCTime, UTCTime } */
        asn1_tlv issuer;
        check_ok("issuer is a SEQUENCE", asn1_expect(&tc, ASN1_SEQUENCE, &issuer) == 0);
        asn1_cursor val; asn1_tlv nb, na;
        int vlok = asn1_open(&tc, ASN1_SEQUENCE, &val) == 0
                && asn1_expect(&val, ASN1_UTCTIME, &nb) == 0
                && asn1_expect(&val, ASN1_UTCTIME, &na) == 0;
        check_ok("validity has two UTCTime fields", vlok);
        check_ok("notBefore == 160730012359Z",
                 vlok && nb.len == 13 && memcmp(nb.value, "160730012359Z", 13) == 0);
    }

    printf("X.509 parser — RFC 8448 server certificate:\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("version == 2 (v3)", cert.version == 2);
        check_ok("serialNumber == 2", cert.serial.len == 1 && cert.serial.p[0] == 2);
        check_ok("issuer CN == \"rsa\"", strcmp(cert.issuer_cn, "rsa") == 0);
        check_ok("subject CN == \"rsa\"", strcmp(cert.subject_cn, "rsa") == 0);
        check_ok("public key algorithm == RSA", cert.pubkey_algo == X509_PK_RSA);
        check_ok("SPKI length == 162 (full element)", cert.spki.len == 162);
        check_ok("TBSCertificate length == 281 (full element)", cert.tbs.len == 281);
        check_ok("signatureValue length == 128 (RSA-1024)", cert.signature.len == 128);
        static const uint8_t oid_sha256rsa[] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
        check_ok("signature OID == sha256WithRSAEncryption",
                 x509_slice_eq(&cert.sig_oid, oid_sha256rsa, sizeof oid_sha256rsa));
        check_ok("notBefore == 2016-07-30 01:23:59Z (1469841839)", cert.not_before == 1469841839ULL);
        check_ok("notAfter  == 2026-07-30 01:23:59Z (1785374639)", cert.not_after == 1785374639ULL);
        check_ok("notBefore < notAfter", cert.not_before < cert.not_after);
        check_ok("no SAN entries", cert.san_count == 0);
    }

    printf("X.509 parser — synthetic certificate with SubjectAltName:\n");
    {
        uint8_t der[512];
        int derlen = unhex(SAN_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("subject CN == \"example.com\"", strcmp(cert.subject_cn, "example.com") == 0);
        check_ok("issuer CN == \"Test CA\"", strcmp(cert.issuer_cn, "Test CA") == 0);
        check_ok("public key algorithm == RSA", cert.pubkey_algo == X509_PK_RSA);
        check_ok("san_count == 2", cert.san_count == 2);
        check_ok("SAN[0] == example.com",     san_is(&cert, 0, "example.com"));
        check_ok("SAN[1] == www.example.com", san_is(&cert, 1, "www.example.com"));
        check_ok("notBefore == 2024-01-01Z (1704067200)", cert.not_before == 1704067200ULL);
        check_ok("notAfter  == 2034-01-01Z (2019686400)", cert.not_after == 2019686400ULL);
    }

    printf("X.509 signature — RFC 8448 self-signed certificate (end-to-end PKI):\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);

        /* self-signed: the issuer key is the cert's own SubjectPublicKey */
        int rc = x509_verify_signature(&cert, cert.spki_key.p, cert.spki_key.len);
        check_ok("RSA/SHA-256 signature verifies over TBSCertificate", rc == X509_VERIFY_OK);

        /* flip one byte inside the TBSCertificate -> signature must fail */
        uint8_t der2[512]; memcpy(der2, der, derlen);
        x509_cert cert2;
        check_ok("tampered cert re-parses", x509_parse(der2, derlen, &cert2) == 0);
        /* cert2.tbs points into der2; corrupt its first content byte */
        der2[(cert2.tbs.p - der2) + 8] ^= 1;
        check_ok("tampered TBSCertificate -> BAD_SIGNATURE",
                 x509_verify_signature(&cert2, cert2.spki_key.p, cert2.spki_key.len) == X509_VERIFY_BAD_SIGNATURE);

        /* dispatcher: a genuinely unimplemented algorithm (ecdsa-with-SHA512) is
         * reported UNSUPPORTED, not failed. ecdsa-with-SHA256/SHA384 are supported
         * and exercised against real ECDSA certs below. */
        static const uint8_t oid_ecdsa512[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04 };
        x509_cert fake = cert;
        fake.sig_oid.p = oid_ecdsa512; fake.sig_oid.len = sizeof oid_ecdsa512;
        check_ok("unimplemented signature algorithm -> UNSUPPORTED",
                 x509_verify_signature(&fake, cert.spki_key.p, cert.spki_key.len) == X509_VERIFY_UNSUPPORTED);
    }

    printf("X.509 signature — ECDSA P-256 / SHA-256 self-signed certificate (13.x.4):\n");
    {
        uint8_t der[512];
        int derlen = unhex(EC_CERT, der);
        x509_cert cert;
        check_ok("ECDSA certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("public key algorithm == EC (prime256v1 named curve checked)",
                 cert.pubkey_algo == X509_PK_EC);
        check_ok("subject CN == \"aurora-ec-test\"", strcmp(cert.subject_cn, "aurora-ec-test") == 0);
        check_ok("SAN[0] == aurora-ec-test",
                 cert.san_count == 1 && san_is(&cert, 0, "aurora-ec-test"));
        static const uint8_t oid_ecdsa256[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };
        check_ok("signature OID == ecdsa-with-SHA256",
                 x509_slice_eq(&cert.sig_oid, oid_ecdsa256, sizeof oid_ecdsa256));
        check_ok("EC subjectPublicKey is 65-byte uncompressed point",
                 cert.spki_key.len == 65 && cert.spki_key.p[0] == 0x04);

        /* KAT #1 — positive: the self-signed ECDSA signature verifies over its
         * own TBSCertificate (issuer key = the cert's own SubjectPublicKey). */
        int rc = x509_verify_signature(&cert, cert.spki_key.p, cert.spki_key.len);
        check_ok("KAT#1 ECDSA/SHA-256 signature verifies (cert -> PASS)", rc == X509_VERIFY_OK);
        x509_cert roots[] = { cert };
        check_ok("KAT#1 trusts itself as a root via x509_verify_chain",
                 x509_verify_chain(&cert, 1, roots, 1) == X509_VERIFY_OK);

        /* KAT #2 — tamper TBSCertificate: flip one content byte (the version
         * value); the cert still parses but SHA-256(tbs) changes, so the
         * signature must no longer verify. Proves the signature is actually
         * checked against the body, not merely that the structure is well-formed. */
        uint8_t der2[512]; memcpy(der2, der, derlen);
        x509_cert cert2;
        check_ok("tampered-TBS cert re-parses", x509_parse(der2, derlen, &cert2) == 0);
        der2[(cert2.tbs.p - der2) + 8] ^= 1;
        check_ok("KAT#2 tampered TBSCertificate -> BAD_SIGNATURE (cert -> FAIL)",
                 x509_verify_signature(&cert2, cert2.spki_key.p, cert2.spki_key.len)
                     == X509_VERIFY_BAD_SIGNATURE);

        /* KAT #3 — tamper the signature: flip the last byte of the ECDSA-Sig-Value
         * (changes s). The DER still parses strictly but the verification
         * equation fails. Exercises the dispatcher + DER signature path. */
        uint8_t der3[512]; memcpy(der3, der, derlen);
        x509_cert cert3;
        check_ok("tampered-signature cert re-parses", x509_parse(der3, derlen, &cert3) == 0);
        der3[(cert3.signature.p - der3) + cert3.signature.len - 1] ^= 1;
        check_ok("KAT#3 tampered signature -> BAD_SIGNATURE (cert -> FAIL)",
                 x509_verify_signature(&cert3, cert3.spki_key.p, cert3.spki_key.len)
                     == X509_VERIFY_BAD_SIGNATURE);
    }

    printf("X.509 trust chain / validity / hostname (synthetic CA + leaf):\n");
    {
        /* CA is self-signed; LEAF is signed by CA, SAN = example.com,
         * www.example.com, *.test.example (from tools/mkchain). */
        #define CA_CERT   "308201a63082010fa003020102020101300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3019311730150603550403130e4175726f7261205465737420434130819f300d06092a864886f70d010101050003818d0030818902818100914dc084000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007732cf66ae551d9f99d4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054abb024451f79ca150203010001300d06092a864886f70d01010b0500038181005aa1a47ee6e84e6bbe29bcb16207087ecfccdbc66214a6c372379ba64d43212d6a496094f564ffe12686ec80517c213d7cc7a295d5efe29917527f36f29599d87031603b8f880864c21fb0fc6723f122230faa66ad05ef17189079508995c42f7aad0850a3844a157ba21a6d0952a4a294bd418a56219eecd1a3430b0fe7323f"
        #define LEAF_CERT "308201e030820149a003020102020102300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d30819f300d06092a864886f70d010101050003818d00308189028181008e67a321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007600e22250a7f8ade8900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282c15e8195233abef0203010001a33b303930370603551d110430302e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d820e2a2e746573742e6578616d706c65300d06092a864886f70d01010b050003818100480244df1797489d5f5dd3e84f7f0cbdc9a6f573f22ea7825feccf7a3c13f500e04119491314baa8853e90f5a449d398b8e34e3bf75df7f436d79382d32734978e44870f65c47064c95843197cd8e44b36b6cd6f69753bb33401e9d90a3256965d0a46d199586cf7c6b836a443460995663c4501034f40dd46816071e9d8f951"

        uint8_t cad[512], leafd[512], rfcd[512];
        x509_cert ca, leaf, rfc;
        check_ok("CA parses",   x509_parse(cad,   unhex(CA_CERT, cad),    &ca)   == 0);
        check_ok("leaf parses", x509_parse(leafd, unhex(LEAF_CERT, leafd), &leaf) == 0);
        x509_parse(rfcd, unhex(RFC_DER_CERT, rfcd), &rfc);

        /* 12.4a — trust chain */
        x509_cert roots_good[] = { ca };
        check_ok("leaf trusted by CA root", x509_verify_chain(&leaf, 1, roots_good, 1) == X509_VERIFY_OK);
        x509_cert roots_bad[] = { rfc };       /* an unrelated self-signed root */
        check_ok("leaf NOT trusted by unrelated root",
                 x509_verify_chain(&leaf, 1, roots_bad, 1) == X509_VERIFY_UNTRUSTED);
        check_ok("CA verifies itself (self-signed)", x509_verify_chain(&ca, 1, roots_good, 1) == X509_VERIFY_OK);

        /* 12.4b — validity window (cert valid 2024-01-01 .. 2034-01-01) */
        check_ok("valid in 2026",     x509_check_validity(&leaf, 1767225600ULL) == X509_VALID_OK);
        check_ok("not yet valid 2023", x509_check_validity(&leaf, 1700000000ULL) == X509_VALID_NOT_YET);
        check_ok("expired 2035",      x509_check_validity(&leaf, 2050000000ULL) == X509_VALID_EXPIRED);

        /* 12.4c — hostname (SAN dNSName, CN ignored, one-level wildcard) */
        check_ok("exact: example.com",          x509_check_hostname(&leaf, "example.com") == 0);
        check_ok("exact: www.example.com",      x509_check_hostname(&leaf, "www.example.com") == 0);
        check_ok("case-insensitive: WWW.Example.Com", x509_check_hostname(&leaf, "WWW.Example.Com") == 0);
        check_ok("wildcard: foo.test.example",  x509_check_hostname(&leaf, "foo.test.example") == 0);
        check_ok("wildcard rejects two labels: a.b.test.example",
                 x509_check_hostname(&leaf, "a.b.test.example") == -1);
        check_ok("wildcard rejects bare: test.example",
                 x509_check_hostname(&leaf, "test.example") == -1);
        check_ok("no match: evil.com",          x509_check_hostname(&leaf, "evil.com") == -1);
        check_ok("CN is not used for matching",  x509_check_hostname(&rfc, "rsa") == -1);
    }

    printf("X.509 depth-N path building (14.0.1: leaf -> intermediate -> root):\n");
    {
        uint8_t rootd[700], interd[700], leafd[700];
        x509_cert root, inter, leaf;
        check_ok("root parses",  x509_parse(rootd,  unhex(PKI_ROOT,  rootd),  &root)  == 0);
        check_ok("inter parses", x509_parse(interd, unhex(PKI_INTER, interd), &inter) == 0);
        check_ok("leaf parses",  x509_parse(leafd,  unhex(PKI_LEAF,  leafd),  &leaf)  == 0);
        check_ok("intermediate is a CA with keyCertSign",
                 inter.is_ca == 1 && inter.has_key_usage == 1 && inter.key_cert_sign == 1);
        check_ok("leaf is not a CA", leaf.is_ca == 0);

        x509_cert roots[] = { root };

        /* 14.0.1a — full chain: leaf -> intermediate -> root */
        x509_cert chain2[] = { leaf, inter };
        check_ok("depth-2 chain (leaf,inter) trusted by root",
                 x509_verify_chain(chain2, 2, roots, 1) == X509_VERIFY_OK);

        /* broken issuer chain: leaf alone, no intermediate to bridge to the root */
        check_ok("leaf without intermediate -> UNTRUSTED (broken chain)",
                 x509_verify_chain(&leaf, 1, roots, 1) == X509_VERIFY_UNTRUSTED);

        /* the intermediate itself chains directly to the root (depth-1 sub-path) */
        check_ok("intermediate verified directly by root",
                 x509_verify_chain(&inter, 1, roots, 1) == X509_VERIFY_OK);

        /* 14.0.1b — basicConstraints CA:FALSE used as an issuer -> BAD_CA */
        uint8_t ncad[700], lbd[700];
        x509_cert notca, leaf_b;
        check_ok("notca-inter parses", x509_parse(ncad, unhex(PKI_INTER_NOTCA, ncad), &notca) == 0);
        check_ok("leaf_b parses",      x509_parse(lbd,  unhex(PKI_LEAF_B, lbd),       &leaf_b) == 0);
        check_ok("notca-inter has CA:FALSE", notca.is_ca == 0);
        x509_cert chain_b[] = { leaf_b, notca };
        check_ok("CA:FALSE issuer rejected -> BAD_CA",
                 x509_verify_chain(chain_b, 2, roots, 1) == X509_VERIFY_BAD_CA);

        /* 14.0.1c — CA:TRUE but no keyCertSign used as an issuer -> BAD_CA */
        uint8_t nkd[700], lcd[700];
        x509_cert nokucs, leaf_c;
        check_ok("nokucs-inter parses", x509_parse(nkd, unhex(PKI_INTER_NOKUCS, nkd), &nokucs) == 0);
        check_ok("leaf_c parses",       x509_parse(lcd, unhex(PKI_LEAF_C, lcd),        &leaf_c) == 0);
        check_ok("nokucs-inter is CA but lacks keyCertSign",
                 nokucs.is_ca == 1 && nokucs.has_key_usage == 1 && nokucs.key_cert_sign == 0);
        x509_cert chain_c[] = { leaf_c, nokucs };
        check_ok("CA without keyCertSign rejected -> BAD_CA",
                 x509_verify_chain(chain_c, 2, roots, 1) == X509_VERIFY_BAD_CA);

        /* wrong root: a valid 2-cert chain but the trust anchor is unrelated */
        uint8_t rfcd[700]; x509_cert rfc; x509_parse(rfcd, unhex(RFC_DER_CERT, rfcd), &rfc);
        x509_cert roots_wrong[] = { rfc };
        check_ok("valid chain but untrusted root -> UNTRUSTED",
                 x509_verify_chain(chain2, 2, roots_wrong, 1) == X509_VERIFY_UNTRUSTED);
    }

    printf("X.509 real Let's Encrypt chain, offline (14.0.2: www.eff.org -> ISRG Root X1):\n");
    {
        static uint8_t lf[2048], y1[2048], ry[2048], x1[2048];
        int lflen = unhex(PKI_LE_LEAF, lf), y1len = unhex(PKI_LE_YR1, y1);
        int rylen = unhex(PKI_LE_ROOTYR, ry), x1len = unhex(PKI_ISRG_X1, x1);
        x509_cert leaf, yr1, rootyr, isrg;
        check_ok("LE leaf parses",        x509_parse(lf, lflen, &leaf)   == 0);
        check_ok("LE YR1 parses",         x509_parse(y1, y1len, &yr1)    == 0);
        check_ok("LE Root YR parses",     x509_parse(ry, rylen, &rootyr) == 0);
        check_ok("ISRG Root X1 parses",   x509_parse(x1, x1len, &isrg)   == 0);
        check_ok("intermediates are RSA CAs with keyCertSign",
                 yr1.is_ca && yr1.key_cert_sign && rootyr.is_ca && rootyr.key_cert_sign);

        /* what the server sends: leaf + the two intermediates; anchor = ISRG Root X1 */
        x509_cert chain[]  = { leaf, yr1, rootyr };
        x509_cert anchor[] = { isrg };
        uint64_t now_le = 1782864000ULL;   /* 2026-07-01, inside the leaf's 90-day window */

        /* Case 1 — the real chain validates against ISRG Root X1 (depth-3, all RSA) */
        check_ok("CASE 1: real LE chain trusted by ISRG Root X1 -> OK",
                 x509_verify_chain(chain, 3, anchor, 1) == X509_VERIFY_OK);
        check_ok("CASE 1: leaf within validity at 2026-07-01",
                 x509_check_validity(&leaf, now_le) == X509_VALID_OK);
        check_ok("CASE 1: hostname www.eff.org matches *.eff.org SAN",
                 x509_check_hostname(&leaf, "www.eff.org") == 0);

        /* Case 2 — drop the YR1 bridge: the path can't be built -> UNTRUSTED
         * (distinct from a tampered link; no issuer matched by name) */
        x509_cert chain_missing[] = { leaf, rootyr };
        check_ok("CASE 2: missing intermediate -> UNTRUSTED",
                 x509_verify_chain(chain_missing, 2, anchor, 1) == X509_VERIFY_UNTRUSTED);

        /* Case 3 — tamper YR1's signature (last byte): leaf->YR1 still verifies but
         * YR1->RootYR fails, so the issuer is found by name but rejected -> BAD_SIGNATURE */
        static uint8_t y1bad[2048]; memcpy(y1bad, y1, y1len); y1bad[y1len - 1] ^= 1;
        x509_cert yr1bad;
        check_ok("tampered YR1 re-parses", x509_parse(y1bad, y1len, &yr1bad) == 0);
        x509_cert chain_bad[] = { leaf, yr1bad, rootyr };
        check_ok("CASE 3: tampered intermediate signature -> BAD_SIGNATURE",
                 x509_verify_chain(chain_bad, 3, anchor, 1) == X509_VERIFY_BAD_SIGNATURE);

        /* Case 4 — different trust store: valid chain, unrelated anchor -> UNTRUSTED */
        uint8_t otherd[700]; x509_cert other; x509_parse(otherd, unhex(RFC_DER_CERT, otherd), &other);
        x509_cert other_anchor[] = { other };
        check_ok("CASE 4: different trust store -> UNTRUSTED",
                 x509_verify_chain(chain, 3, other_anchor, 1) == X509_VERIFY_UNTRUSTED);
    }

    {   /* 14.x.4 — P-384 chain: ecdsa-with-SHA384 + secp384r1 through the verifier */
        static uint8_t rd[1024], id[1024], ld[1024];
        int rdl = unhex(PKI384_ROOT, rd), idl = unhex(PKI384_INTER, id), ldl = unhex(PKI384_LEAF, ld);
        x509_cert root, inter, leaf;
        check_ok("P384 root parses",  x509_parse(rd, rdl, &root)  == 0);
        check_ok("P384 inter parses", x509_parse(id, idl, &inter) == 0);
        check_ok("P384 leaf parses",  x509_parse(ld, ldl, &leaf)  == 0);
        check_ok("P384 keys classified as secp384r1 (EC384)",
                 root.pubkey_algo == X509_PK_EC384 && inter.pubkey_algo == X509_PK_EC384 &&
                 leaf.pubkey_algo == X509_PK_EC384);
        check_ok("P384 intermediate is a CA with keyCertSign",
                 inter.is_ca && inter.key_cert_sign);
        check_ok("P384 leaf SAN p384.aurora.test matches",
                 x509_check_hostname(&leaf, "p384.aurora.test") == 0);

        x509_cert chain[]  = { leaf, inter };
        x509_cert anchor[] = { root };
        check_ok("P384 CASE 1: leaf+inter trusted by P384 root -> OK",
                 x509_verify_chain(chain, 2, anchor, 1) == X509_VERIFY_OK);

        /* tamper the intermediate's signature: leaf->inter still verifies but
         * inter->root fails -> BAD_SIGNATURE (issuer found by name, rejected) */
        static uint8_t ibad[1024]; memcpy(ibad, id, idl); ibad[idl - 1] ^= 1;
        x509_cert interbad; check_ok("P384 tampered inter re-parses", x509_parse(ibad, idl, &interbad) == 0);
        x509_cert chain_bad[] = { leaf, interbad };
        check_ok("P384 CASE 2: tampered intermediate signature -> BAD_SIGNATURE",
                 x509_verify_chain(chain_bad, 2, anchor, 1) == X509_VERIFY_BAD_SIGNATURE);

        /* drop the intermediate: no path to the anchor -> UNTRUSTED */
        x509_cert chain_missing[] = { leaf };
        check_ok("P384 CASE 3: missing intermediate -> UNTRUSTED",
                 x509_verify_chain(chain_missing, 1, anchor, 1) == X509_VERIFY_UNTRUSTED);

        /* different trust store -> UNTRUSTED */
        uint8_t otherd[700]; x509_cert other; x509_parse(otherd, unhex(RFC_DER_CERT, otherd), &other);
        x509_cert other_anchor[] = { other };
        check_ok("P384 CASE 4: different trust store -> UNTRUSTED",
                 x509_verify_chain(chain, 2, other_anchor, 1) == X509_VERIFY_UNTRUSTED);
    }

    printf(failures ? "\nX509 TEST: %d FAILURE(S)\n" : "\nX509 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
