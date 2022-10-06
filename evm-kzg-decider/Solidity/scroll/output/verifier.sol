// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Verifier {
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        uint256 length = p1.length * 6;
        uint256[] memory input = new uint256[](length);
        uint256[1] memory result;
        bool ret;

        require(p1.length == p2.length);

        for (uint256 i = 0; i < p1.length; i++) {
            input[0 + i * 6] = p1[i].x;
            input[1 + i * 6] = p1[i].y;
            input[2 + i * 6] = p2[i].x[0];
            input[3 + i * 6] = p2[i].x[1];
            input[4 + i * 6] = p2[i].y[0];
            input[5 + i * 6] = p2[i].y[1];
        }

        assembly {
            ret := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(length, 0x20),
                result,
                0x20
            )
        }
        require(ret);
        return result[0] != 0;
    }

    uint256 constant q_mod =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function fr_invert(uint256 a) internal view returns (uint256) {
        return fr_pow(a, q_mod - 2);
    }

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = q_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_div(uint256 a, uint256 b) internal view returns (uint256) {
        require(b != 0);
        return mulmod(a, fr_invert(b), q_mod);
    }

    function fr_mul_add(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return addmod(mulmod(a, b, q_mod), c, q_mod);
    }

    function fr_mul_add_pm(
        uint256[78] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                t = addmod(mulmod(proof[a], m[b], q_mod), t, q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_mul_add_mt(
        uint256[78] memory m,
        uint256 base,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 1) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                t = addmod(mulmod(base, t, q_mod), m[a], q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }

    uint256 constant p_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function ecc_from(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory r)
    {
        r.x = x;
        r.y = y;
    }

    function ecc_add(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        bool ret = false;
        G1Point memory r;
        uint256[4] memory input_points;

        input_points[0] = ax;
        input_points[1] = ay;
        input_points[2] = bx;
        input_points[3] = by;

        assembly {
            ret := staticcall(gas(), 6, input_points, 0x80, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function ecc_sub(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        return ecc_add(ax, ay, bx, p_mod - by);
    }

    function ecc_mul(uint256 px, uint256 py, uint256 s)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[3] memory input;
        bool ret = false;
        G1Point memory r;

        input[0] = px;
        input[1] = py;
        input[2] = s;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function _ecc_mul_add(uint256[5] memory input)
        internal
        view
    {
        bool ret = false;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, add(input, 0x20), 0x40)
        }
        require(ret);

        assembly {
            ret := staticcall(gas(), 6, add(input, 0x20), 0x80, add(input, 0x60), 0x40)
        }
        require(ret);
    }

    function ecc_mul_add(uint256 px, uint256 py, uint256 s, uint256 qx, uint256 qy)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[5] memory input;
        input[0] = px;
        input[1] = py;
        input[2] = s;
        input[3] = qx;
        input[4] = qy;

        _ecc_mul_add(input);

        return (input[3], input[4]);
    }
    
    function ecc_mul_add_pm(
        uint256[78] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t0,
        uint256 t1
    ) internal view returns (uint256, uint256) {
        uint256[5] memory input;
        input[3] = t0;
        input[4] = t1;
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                input[0] = proof[a];
                input[1] = proof[a + 1];
                input[2] = m[b];
                _ecc_mul_add(input);
            } else {
                break;
            }
        }

        return (input[3], input[4]);
    }

    function update_hash_scalar(uint256 v, uint256[144] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(uint256 x, uint256 y, uint256[144] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v = tmp % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[144] memory absorbing, uint256 length) private view returns (bytes32[1] memory v) {
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 2, absorbing, length, v, 32)
            switch success case 0 { invalid() }
        }
        assert(success);
    }

    function squeeze_challenge(uint256[144] memory absorbing, uint32 length) internal view returns (uint256 v) {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_verify_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256(8927483328158487303192801932586823945966474500171288591217247073080517216428);
        s.x[1] = uint256(7346934330392193658388472328095270585546041216788756361721267098987470397251);
        s.y[0] = uint256(16587628359744171692616926856613555457893980590522340531266287663029455390834);
        s.y[1] = uint256(21820573376703209943520460353885699042421973081770368296207959602624363229555);
    }

    function get_verify_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634);
        n.x[1] = uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781);
        n.y[0] = uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052);
        n.y[1] = uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653);
    }

    function get_target_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256(7584584500749292908655541229471445197909587142488021580331145010668875630560);
        s.x[1] = uint256(8288084436015603290508831272273927291505960418140680056758939392914454797422);
        s.y[0] = uint256(7852356268726264381390689465241557351545047302120841912436290077028674594119);
        s.y[1] = uint256(17511064176458577891274978630714672343024592020300180050302304103633386970516);
    }

    function get_target_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634);
        n.x[1] = uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781);
        n.y[0] = uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052);
        n.y[1] = uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653);
    }

    function get_wx_wg(uint256[] calldata proof, uint256[6] memory instances)
        internal
        view
        returns (uint256, uint256, uint256, uint256)
    {
        uint256[78] memory m;
        uint256[144] memory absorbing;
        uint256 t0 = 0;
        uint256 t1 = 0;

        
        (t0, t1) = (ecc_mul(14261374311072401427794733878303448562361115644982953880630274040067436660315, 18147980404500099408709210923680461499052883834819227991158277474449419744338, instances[0]));
        (t0, t1) = (ecc_mul_add(18995427570368154049628043471974735092565733811141694670877466100479285453839, 12397981549695572321377722101944707237709183836054809563271734043474092582293, instances[1], t0, t1));
        (t0, t1) = (ecc_mul_add(130467041540920965872097151625957623640103768354591412713943512039372772257, 3011981633960416625753793569630171805592662557559517615482351526173379535368, instances[2], t0, t1));
        (t0, t1) = (ecc_mul_add(16661799682909786205333755682884175588136927482067191345693001148408291081843, 19336211856431787225465737281156839286518663726243489277502113118352461506703, instances[3], t0, t1));
        (t0, t1) = (ecc_mul_add(7006928027870044334645006791283963269534364708729698209159883747033438163063, 12274505942597294081470896876425822529540030890762093466082731609766059159514, instances[4], t0, t1));
        (m[0], m[1]) = (ecc_mul_add(8844036781357673617601379082482204331182757307987986180228524507360455336588, 5312538779421557226585341637228429323788768081414433027584153565319449889567, instances[5], t0, t1));
        update_hash_scalar(19529910927257824234742707975883475492291391581527887590946735268776592535279, absorbing, 0);
        update_hash_point(m[0], m[1], absorbing, 2);
        for (t0 = 0; t0 <= 4; t0++) {
            update_hash_point(proof[0 + t0 * 2], proof[1 + t0 * 2], absorbing, 5 + t0 * 3);
        }
        m[2] = (squeeze_challenge(absorbing, 20));
        for (t0 = 0; t0 <= 13; t0++) {
            update_hash_point(proof[10 + t0 * 2], proof[11 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[3] = (squeeze_challenge(absorbing, 43));
        m[4] = (squeeze_challenge(absorbing, 1));
        for (t0 = 0; t0 <= 9; t0++) {
            update_hash_point(proof[38 + t0 * 2], proof[39 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[5] = (squeeze_challenge(absorbing, 31));
        for (t0 = 0; t0 <= 3; t0++) {
            update_hash_point(proof[58 + t0 * 2], proof[59 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[6] = (squeeze_challenge(absorbing, 13));
        for (t0 = 0; t0 <= 70; t0++) {
            update_hash_scalar(proof[66 + t0 * 1], absorbing, 1 + t0 * 2);
        }
        m[7] = (squeeze_challenge(absorbing, 143));
        m[8] = (squeeze_challenge(absorbing, 1));
        for (t0 = 0; t0 <= 3; t0++) {
            update_hash_point(proof[137 + t0 * 2], proof[138 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[9] = (mulmod(m[6], 11211301017135681023579411905410872569206244553457844956874280139879520583390, q_mod));
        m[10] = (mulmod(m[6], 10939663269433627367777756708678102241564365262857670666700619874077960926249, q_mod));
        m[11] = (mulmod(m[6], 8734126352828345679573237859165904705806588461301144420590422589042130041188, q_mod));
        m[12] = (fr_pow(m[6], 4194304));
        m[13] = (addmod(m[12], q_mod - 1, q_mod));
        m[14] = (mulmod(21888237653275510688422624196183639687472264873923820041627027729598873448513, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 1, q_mod));
        m[14] = (fr_div(m[14], t0));
        m[15] = (mulmod(12919475148704033459056799975164749366765443418491560826543287262494049147445, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 8734126352828345679573237859165904705806588461301144420590422589042130041188, q_mod));
        m[15] = (fr_div(m[15], t0));
        m[16] = (mulmod(2475562068482919789434538161456555368473369493180072113639899532770322825977, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 2785514556381676080176937710880804108647911392478702105860685610379369825016, q_mod));
        m[16] = (fr_div(m[16], t0));
        m[17] = (mulmod(9952375098572582562392692839581731570430874250722926349774599560449354965478, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 21710372849001950800533397158415938114909991150039389063546734567764856596059, q_mod));
        m[17] = (fr_div(m[17], t0));
        m[18] = (mulmod(20459617746544248062014976317203465365908990827508925305769002868034509119086, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 15402826414547299628414612080036060696555554914079673875872749760617770134879, q_mod));
        m[18] = (fr_div(m[18], t0));
        m[19] = (mulmod(496209762031177553439375370250532367801224970379575774747024844773905018536, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 11016257578652593686382655500910603527869149377564754001549454008164059876499, q_mod));
        m[19] = (fr_div(m[19], t0));
        m[20] = (mulmod(20023042075029862075635603136649050502962424708267292886390647475108663608857, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 10939663269433627367777756708678102241564365262857670666700619874077960926249, q_mod));
        m[20] = (fr_div(m[20], t0));
        t0 = (addmod(m[15], m[16], q_mod));
        t0 = (addmod(t0, m[17], q_mod));
        t0 = (addmod(t0, m[18], q_mod));
        m[15] = (addmod(t0, m[19], q_mod));
        t0 = (fr_mul_add(proof[74], proof[72], proof[73]));
        t0 = (fr_mul_add(proof[75], proof[67], t0));
        t0 = (fr_mul_add(proof[76], proof[68], t0));
        t0 = (fr_mul_add(proof[77], proof[69], t0));
        t0 = (fr_mul_add(proof[78], proof[70], t0));
        m[16] = (fr_mul_add(proof[79], proof[71], t0));
        t0 = (mulmod(proof[67], proof[68], q_mod));
        m[16] = (fr_mul_add(proof[80], t0, m[16]));
        t0 = (mulmod(proof[69], proof[70], q_mod));
        m[16] = (fr_mul_add(proof[81], t0, m[16]));
        t0 = (addmod(1, q_mod - proof[97], q_mod));
        m[17] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[100], proof[100], q_mod));
        t0 = (addmod(t0, q_mod - proof[100], q_mod));
        m[18] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(proof[100], q_mod - proof[99], q_mod));
        m[19] = (mulmod(t0, m[14], q_mod));
        m[21] = (mulmod(m[3], m[6], q_mod));
        t0 = (addmod(m[20], m[15], q_mod));
        m[15] = (addmod(1, q_mod - t0, q_mod));
        m[22] = (addmod(proof[67], m[4], q_mod));
        t0 = (fr_mul_add(proof[91], m[3], m[22]));
        m[23] = (mulmod(t0, proof[98], q_mod));
        t0 = (addmod(m[22], m[21], q_mod));
        m[22] = (mulmod(t0, proof[97], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[68], m[4], q_mod));
        t0 = (fr_mul_add(proof[92], m[3], m[25]));
        m[23] = (mulmod(t0, m[23], q_mod));
        t0 = (addmod(m[25], m[24], q_mod));
        m[22] = (mulmod(t0, m[22], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[24], q_mod));
        m[25] = (addmod(proof[69], m[4], q_mod));
        t0 = (fr_mul_add(proof[93], m[3], m[25]));
        m[23] = (mulmod(t0, m[23], q_mod));
        t0 = (addmod(m[25], m[24], q_mod));
        m[22] = (mulmod(t0, m[22], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[24], q_mod));
        t0 = (addmod(m[23], q_mod - m[22], q_mod));
        m[22] = (mulmod(t0, m[15], q_mod));
        m[21] = (mulmod(m[21], 11166246659983828508719468090013646171463329086121580628794302409516816350802, q_mod));
        m[23] = (addmod(proof[70], m[4], q_mod));
        t0 = (fr_mul_add(proof[94], m[3], m[23]));
        m[24] = (mulmod(t0, proof[101], q_mod));
        t0 = (addmod(m[23], m[21], q_mod));
        m[23] = (mulmod(t0, proof[100], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[71], m[4], q_mod));
        t0 = (fr_mul_add(proof[95], m[3], m[25]));
        m[24] = (mulmod(t0, m[24], q_mod));
        t0 = (addmod(m[25], m[21], q_mod));
        m[23] = (mulmod(t0, m[23], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[66], m[4], q_mod));
        t0 = (fr_mul_add(proof[96], m[3], m[25]));
        m[24] = (mulmod(t0, m[24], q_mod));
        t0 = (addmod(m[25], m[21], q_mod));
        m[23] = (mulmod(t0, m[23], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        t0 = (addmod(m[24], q_mod - m[23], q_mod));
        m[21] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[104], m[3], q_mod));
        m[23] = (mulmod(proof[103], t0, q_mod));
        t0 = (addmod(proof[106], m[4], q_mod));
        m[23] = (mulmod(m[23], t0, q_mod));
        m[24] = (mulmod(proof[67], proof[82], q_mod));
        m[2] = (mulmod(0, m[2], q_mod));
        m[24] = (addmod(m[2], m[24], q_mod));
        m[25] = (addmod(m[2], proof[83], q_mod));
        m[26] = (addmod(proof[104], q_mod - proof[106], q_mod));
        t0 = (addmod(1, q_mod - proof[102], q_mod));
        m[27] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[102], proof[102], q_mod));
        t0 = (addmod(t0, q_mod - proof[102], q_mod));
        m[28] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[24], m[3], q_mod));
        m[24] = (mulmod(proof[102], t0, q_mod));
        m[25] = (addmod(m[25], m[4], q_mod));
        t0 = (mulmod(m[24], m[25], q_mod));
        t0 = (addmod(m[23], q_mod - t0, q_mod));
        m[23] = (mulmod(t0, m[15], q_mod));
        m[24] = (mulmod(m[14], m[26], q_mod));
        t0 = (addmod(proof[104], q_mod - proof[105], q_mod));
        t0 = (mulmod(m[26], t0, q_mod));
        m[26] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[109], m[3], q_mod));
        m[29] = (mulmod(proof[108], t0, q_mod));
        t0 = (addmod(proof[111], m[4], q_mod));
        m[29] = (mulmod(m[29], t0, q_mod));
        m[30] = (fr_mul_add(proof[82], proof[68], m[2]));
        m[31] = (addmod(proof[109], q_mod - proof[111], q_mod));
        t0 = (addmod(1, q_mod - proof[107], q_mod));
        m[32] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[107], proof[107], q_mod));
        t0 = (addmod(t0, q_mod - proof[107], q_mod));
        m[33] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[30], m[3], q_mod));
        t0 = (mulmod(proof[107], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[29], q_mod - t0, q_mod));
        m[29] = (mulmod(t0, m[15], q_mod));
        m[30] = (mulmod(m[14], m[31], q_mod));
        t0 = (addmod(proof[109], q_mod - proof[110], q_mod));
        t0 = (mulmod(m[31], t0, q_mod));
        m[31] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[114], m[3], q_mod));
        m[34] = (mulmod(proof[113], t0, q_mod));
        t0 = (addmod(proof[116], m[4], q_mod));
        m[34] = (mulmod(m[34], t0, q_mod));
        m[35] = (fr_mul_add(proof[82], proof[69], m[2]));
        m[36] = (addmod(proof[114], q_mod - proof[116], q_mod));
        t0 = (addmod(1, q_mod - proof[112], q_mod));
        m[37] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[112], proof[112], q_mod));
        t0 = (addmod(t0, q_mod - proof[112], q_mod));
        m[38] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[35], m[3], q_mod));
        t0 = (mulmod(proof[112], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[34], q_mod - t0, q_mod));
        m[34] = (mulmod(t0, m[15], q_mod));
        m[35] = (mulmod(m[14], m[36], q_mod));
        t0 = (addmod(proof[114], q_mod - proof[115], q_mod));
        t0 = (mulmod(m[36], t0, q_mod));
        m[36] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[119], m[3], q_mod));
        m[39] = (mulmod(proof[118], t0, q_mod));
        t0 = (addmod(proof[121], m[4], q_mod));
        m[39] = (mulmod(m[39], t0, q_mod));
        m[40] = (fr_mul_add(proof[82], proof[70], m[2]));
        m[41] = (addmod(proof[119], q_mod - proof[121], q_mod));
        t0 = (addmod(1, q_mod - proof[117], q_mod));
        m[42] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[117], proof[117], q_mod));
        t0 = (addmod(t0, q_mod - proof[117], q_mod));
        m[43] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[40], m[3], q_mod));
        t0 = (mulmod(proof[117], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[39], q_mod - t0, q_mod));
        m[25] = (mulmod(t0, m[15], q_mod));
        m[39] = (mulmod(m[14], m[41], q_mod));
        t0 = (addmod(proof[119], q_mod - proof[120], q_mod));
        t0 = (mulmod(m[41], t0, q_mod));
        m[40] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[124], m[3], q_mod));
        m[41] = (mulmod(proof[123], t0, q_mod));
        t0 = (addmod(proof[126], m[4], q_mod));
        m[41] = (mulmod(m[41], t0, q_mod));
        m[44] = (fr_mul_add(proof[84], proof[67], m[2]));
        m[45] = (addmod(m[2], proof[85], q_mod));
        m[46] = (addmod(proof[124], q_mod - proof[126], q_mod));
        t0 = (addmod(1, q_mod - proof[122], q_mod));
        m[47] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[122], proof[122], q_mod));
        t0 = (addmod(t0, q_mod - proof[122], q_mod));
        m[48] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[44], m[3], q_mod));
        m[44] = (mulmod(proof[122], t0, q_mod));
        t0 = (addmod(m[45], m[4], q_mod));
        t0 = (mulmod(m[44], t0, q_mod));
        t0 = (addmod(m[41], q_mod - t0, q_mod));
        m[41] = (mulmod(t0, m[15], q_mod));
        m[44] = (mulmod(m[14], m[46], q_mod));
        t0 = (addmod(proof[124], q_mod - proof[125], q_mod));
        t0 = (mulmod(m[46], t0, q_mod));
        m[45] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[129], m[3], q_mod));
        m[46] = (mulmod(proof[128], t0, q_mod));
        t0 = (addmod(proof[131], m[4], q_mod));
        m[46] = (mulmod(m[46], t0, q_mod));
        m[49] = (fr_mul_add(proof[86], proof[67], m[2]));
        m[50] = (addmod(m[2], proof[87], q_mod));
        m[51] = (addmod(proof[129], q_mod - proof[131], q_mod));
        t0 = (addmod(1, q_mod - proof[127], q_mod));
        m[52] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[127], proof[127], q_mod));
        t0 = (addmod(t0, q_mod - proof[127], q_mod));
        m[53] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[49], m[3], q_mod));
        m[49] = (mulmod(proof[127], t0, q_mod));
        t0 = (addmod(m[50], m[4], q_mod));
        t0 = (mulmod(m[49], t0, q_mod));
        t0 = (addmod(m[46], q_mod - t0, q_mod));
        m[46] = (mulmod(t0, m[15], q_mod));
        m[49] = (mulmod(m[14], m[51], q_mod));
        t0 = (addmod(proof[129], q_mod - proof[130], q_mod));
        t0 = (mulmod(m[51], t0, q_mod));
        m[50] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[134], m[3], q_mod));
        m[51] = (mulmod(proof[133], t0, q_mod));
        t0 = (addmod(proof[136], m[4], q_mod));
        m[51] = (mulmod(m[51], t0, q_mod));
        m[54] = (fr_mul_add(proof[88], proof[67], m[2]));
        m[2] = (addmod(m[2], proof[89], q_mod));
        m[55] = (addmod(proof[134], q_mod - proof[136], q_mod));
        t0 = (addmod(1, q_mod - proof[132], q_mod));
        m[56] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[132], proof[132], q_mod));
        t0 = (addmod(t0, q_mod - proof[132], q_mod));
        m[20] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[54], m[3], q_mod));
        m[3] = (mulmod(proof[132], t0, q_mod));
        t0 = (addmod(m[2], m[4], q_mod));
        t0 = (mulmod(m[3], t0, q_mod));
        t0 = (addmod(m[51], q_mod - t0, q_mod));
        m[2] = (mulmod(t0, m[15], q_mod));
        m[3] = (mulmod(m[14], m[55], q_mod));
        t0 = (addmod(proof[134], q_mod - proof[135], q_mod));
        t0 = (mulmod(m[55], t0, q_mod));
        m[4] = (mulmod(t0, m[15], q_mod));
        t0 = (fr_mul_add(m[5], 0, m[16]));
        t0 = (fr_mul_add_mt(m, m[5], 24064768791442479290152634096194013545513974547709823832001394403118888981009, t0));
        t0 = (fr_mul_add_mt(m, m[5], 4704208815882882920750, t0));
        m[2] = (fr_div(t0, m[13]));
        m[3] = (mulmod(m[8], m[8], q_mod));
        m[4] = (mulmod(m[3], m[8], q_mod));
        (t0, t1) = (ecc_mul(proof[137], proof[138], m[4]));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 281470825202571, t0, t1));
        (m[14], m[15]) = (ecc_add(t0, t1, proof[143], proof[144]));
        m[5] = (mulmod(m[4], m[10], q_mod));
        m[10] = (mulmod(m[4], proof[99], q_mod));
        m[11] = (mulmod(m[3], m[11], q_mod));
        m[13] = (mulmod(m[3], m[7], q_mod));
        m[16] = (mulmod(m[13], m[7], q_mod));
        m[17] = (mulmod(m[16], m[7], q_mod));
        m[18] = (mulmod(m[17], m[7], q_mod));
        m[19] = (mulmod(m[18], m[7], q_mod));
        m[20] = (mulmod(m[19], m[7], q_mod));
        t0 = (mulmod(m[20], proof[105], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 5192218722096118505335019273393006, t0));
        m[10] = (addmod(m[10], t0, q_mod));
        m[6] = (mulmod(m[8], m[6], q_mod));
        m[21] = (mulmod(m[8], m[7], q_mod));
        for (t0 = 0; t0 < 52; t0++) {
            m[22 + t0 * 1] = (mulmod(m[21 + t0 * 1], m[7 + t0 * 0], q_mod));
        }
        t0 = (mulmod(m[73], proof[66], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 25987190009742107077980742527956132804769685504365379353571332812354881865795, t0));
        t0 = (fr_mul_add_pm(m, proof, 18679399068738585913008893864493214572484549614980916660536066406366626396277, t0));
        t0 = (fr_mul_add_pm(m, proof, 11472319920207072041878598272885343947088038914199705598762544978176638855245, t0));
        t0 = (fr_mul_add_pm(m, proof, 281471073851486, t0));
        m[74] = (fr_mul_add(proof[96], m[22], t0));
        m[75] = (mulmod(m[21], m[12], q_mod));
        m[76] = (mulmod(m[75], m[12], q_mod));
        m[12] = (mulmod(m[76], m[12], q_mod));
        t0 = (fr_mul_add(m[21], m[2], m[74]));
        t0 = (fr_mul_add(proof[90], m[8], t0));
        m[2] = (addmod(m[10], t0, q_mod));
        m[4] = (addmod(m[4], m[67], q_mod));
        m[10] = (addmod(m[20], m[64], q_mod));
        m[19] = (addmod(m[19], m[61], q_mod));
        m[18] = (addmod(m[18], m[58], q_mod));
        m[17] = (addmod(m[17], m[55], q_mod));
        m[16] = (addmod(m[16], m[52], q_mod));
        m[13] = (addmod(m[13], m[49], q_mod));
        m[3] = (addmod(m[3], m[46], q_mod));
        m[20] = (mulmod(m[7], m[7], q_mod));
        m[46] = (mulmod(m[20], m[7], q_mod));
        for (t0 = 0; t0 < 6; t0++) {
            m[49 + t0 * 3] = (mulmod(m[46 + t0 * 3], m[7 + t0 * 0], q_mod));
        }
        t0 = (mulmod(m[64], proof[72], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 22300414885789078225200772312192282479902050, t0));
        m[67] = (addmod(t0, proof[133], q_mod));
        m[64] = (addmod(m[68], m[64], q_mod));
        m[2] = (addmod(m[2], m[67], q_mod));
        m[4] = (addmod(m[4], m[61], q_mod));
        m[58] = (addmod(m[66], m[58], q_mod));
        m[55] = (addmod(m[65], m[55], q_mod));
        m[52] = (addmod(m[62], m[52], q_mod));
        m[49] = (addmod(m[59], m[49], q_mod));
        m[46] = (addmod(m[56], m[46], q_mod));
        m[20] = (addmod(m[53], m[20], q_mod));
        m[7] = (addmod(m[50], m[7], q_mod));
        m[47] = (addmod(m[47], 1, q_mod));
        (t0, t1) = (ecc_mul(proof[137], proof[138], m[5]));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 95779547201103344574663521248920622570100289727824934, t0, t1));
        (t0, t1) = (ecc_mul_add(m[0], m[1], m[73], t0, t1));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 23117566384181460736372107411586488455996274321045495459183463611775605426176, t0, t1));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 1208910625647296115640116, t0, t1));
        (t0, t1) = (ecc_mul_add(20598352914310034607088081908303438089196773515587935237070814017852255351946, 12481277156278409240971617171856942311190751593180561874418925226922374900137, m[44], t0, t1));
        (t0, t1) = (ecc_mul_add(16171526999132383131398293245232388513469395153294981538278486082069797796361, 5497962545495928279069292238121363782119199231930336401307791352514334566584, m[43], t0, t1));
        (t0, t1) = (ecc_mul_add(12616342181287866720428393114987059140192364685180849577229006289629157569969, 20947142940865007813901824061644257636115947340483319171908118511994706046349, m[42], t0, t1));
        (t0, t1) = (ecc_mul_add(9103687279884947780929707075743229834669183648969979207544221594975681065478, 19383671524536172451680682290058253488791319443838636542307421471403576171750, m[41], t0, t1));
        (t0, t1) = (ecc_mul_add(3836865957786066974080760637649435378069110399235838232427359812230412495171, 9303448757180429646516621272394765206937126270569893520072940781779882015754, m[40], t0, t1));
        (t0, t1) = (ecc_mul_add(4787713354495454480687964552744688847709364185002525396162372464462664645099, 3237520323667000107527931123443271998047446431827668993844850896874897717749, m[39], t0, t1));
        (t0, t1) = (ecc_mul_add(17580357890038487342713430305078799352517216212189423222279448561646247221556, 10578596364459249524044954027950380283732828163803116017382214772158792321962, m[38], t0, t1));
        (t0, t1) = (ecc_mul_add(13313550321750880917464061889822726241775266478387424416861501521359379405056, 14385986661360526447790907687274565766807723834985905138630788366633459929354, m[37], t0, t1));
        (t0, t1) = (ecc_mul_add(2842187960724062548656072387337222544866169646261229131701165700834059530552, 6707597364269064069791805021834568598291753033407177790569927810846156034394, m[36], t0, t1));
        (t0, t1) = (ecc_mul_add(13856656469161621523677608176330089825343322110505749932699413624485985625439, 18968166661824820310014902671812760442894226206593882673493365785595961273565, m[35], t0, t1));
        (t0, t1) = (ecc_mul_add(17425401970862219834729610515642279801423605748378956238195450264444974769886, 13633313867929886549099491238746881585412438500007066131079894641249317301915, m[34], t0, t1));
        (t0, t1) = (ecc_mul_add(11818515676831638379485414492372983978503391214259779702864905522118415515167, 17266988703918752767605711700070176277001039070994752221604055243291315594103, m[33], t0, t1));
        (t0, t1) = (ecc_mul_add(12013572691062766231533661154549753682590351838732028852719676246539384028681, 13554438827358128275848192926362133125799423682221604592686754748210201335419, m[32], t0, t1));
        (t0, t1) = (ecc_mul_add(20044784786226710307974228712907350854687561452518399683032246069340006148295, 5751651836209088226882710435790635797049871067053779911746273458927673623462, m[31], t0, t1));
        (t0, t1) = (ecc_mul_add(20983644603268382247386602944583329352094927050628208933977029372877968334205, 18341613432405461809339082838342744761376822150831911405812900315528858334148, m[30], t0, t1));
        (t0, t1) = (ecc_mul_add(11791947609793249043261524079199734255455532483706000288248845047159770846033, 14527948663784691182071893521884938284790353986700419687650148745717369863342, m[29], t0, t1));
        (t0, t1) = (ecc_mul_add(12013572691062766231533661154549753682590351838732028852719676246539384028681, 13554438827358128275848192926362133125799423682221604592686754748210201335419, m[28], t0, t1));
        (t0, t1) = (ecc_mul_add(19969156353479586914499860705614078548583029221209695462736348971979346988740, 7609415469813302787681025714604792026941693687925239396460835990712668980932, m[27], t0, t1));
        (t0, t1) = (ecc_mul_add(3787739057884773819015873269908762182914758229324165458746729720765261286651, 8486241947123730913305764745882687374275091912451761677965528674498583846615, m[26], t0, t1));
        (t0, t1) = (ecc_mul_add(275591649944305279252560248287765931724975929183779151546474920518304278194, 1806847553984882845584669769039454633132182614204923030906305203419231277866, m[25], t0, t1));
        (t0, t1) = (ecc_mul_add(17146079342005458849393152282935361195911332246861988768210368472504490239638, 16811001469011607179443970912076585093838907238239352415370754748480379814354, m[24], t0, t1));
        (t0, t1) = (ecc_mul_add(3725432901183595634880124057661219038673257981251152757811587884763494692319, 10213772214163870791836740206273923308706543429865021059087222194866409848470, m[23], t0, t1));
        (t0, t1) = (ecc_mul_add(7857890192583848401809171689826743363021284399269591862581759519973283943495, 12737475735578040237915214288503433656210871169343302320009331564470927259703, m[22], t0, t1));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 79226992401923871795060804672, t0, t1));
        (m[0], m[1]) = (ecc_mul_add(proof[143], proof[144], m[9], t0, t1));
        (t0, t1) = (ecc_mul(1, 2, m[2]));
        (m[0], m[1]) = (ecc_sub(m[0], m[1], t0, t1));
        return (m[14], m[15], m[0], m[1]);
    }

    function verify(
        uint256[] calldata proof,
        uint256[] calldata target_circuit_final_pair
    ) public view {
        uint256[6] memory instances;
        instances[0] = target_circuit_final_pair[0] & ((1 << 136) - 1);
        instances[1] = (target_circuit_final_pair[0] >> 136) + ((target_circuit_final_pair[1] & 1) << 136);
        instances[2] = target_circuit_final_pair[2] & ((1 << 136) - 1);
        instances[3] = (target_circuit_final_pair[2] >> 136) + ((target_circuit_final_pair[3] & 1) << 136);
        
        instances[4] = target_circuit_final_pair[4];
        instances[5] = target_circuit_final_pair[5];

        uint256 x0 = 0;
        uint256 x1 = 0;
        uint256 y0 = 0;
        uint256 y1 = 0;

        G1Point[] memory g1_points = new G1Point[](2);
        G2Point[] memory g2_points = new G2Point[](2);
        bool checked = false;

        (x0, y0, x1, y1) = get_wx_wg(proof, instances);
        g1_points[0].x = x0;
        g1_points[0].y = y0;
        g1_points[1].x = x1;
        g1_points[1].y = y1;
        g2_points[0] = get_verify_circuit_g2_s();
        g2_points[1] = get_verify_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);

        g1_points[0].x = target_circuit_final_pair[0];
        g1_points[0].y = target_circuit_final_pair[1];
        g1_points[1].x = target_circuit_final_pair[2];
        g1_points[1].y = target_circuit_final_pair[3];
        g2_points[0] = get_target_circuit_g2_s();
        g2_points[1] = get_target_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);
    }
}
