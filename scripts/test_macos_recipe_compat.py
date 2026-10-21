#!/usr/bin/env python3
"""Exact recipe policy, resource integrity, and official-layout regressions."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zlib

spec = importlib.util.spec_from_file_location("kumo_macos_recipe_compat", Path(__file__).with_name("macos_recipe_compat.py"))
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)
ORIGINALS = json.loads(zlib.decompress(base64.b85decode((
    'c-p-@i*n;OlE1=LDmB!ONL!ZQTi%Pyc4mAvv8QZL_Nqp6EQ*9AWGIqLP=3Vgf4}YqKmsHs%Sq}yo3#Ws8jXH;1N3t*&K}Yv3uEDh'
    '#bSTg=PB<UJG~zq`s%o+d7d!mmM1*Q(!L{d7V#;MoS5Y-jaeFTCY&@Y9iB$XGG;M+aLPGz79o5%n-|%FFBgu;mPNz>X*B2eY@CkM'
    'ADqtx^CnB4l+LG5zy9KsS(Zd|oHfk~2UfdhDTf6B`fHNhFTRaoq!2tyofBtg<PZJrak?xL_%<)gTpVw0&3HLqPW&iaZ1MlOzPV%3'
    'd<&;~i!jOrEf!C*a;sno3k4HfdiPsDx(at+F=8u9!gThYX15-CA#%lw!{ULbJG=h2UxtPM`1?532!kn4SQ;)EQ1{0$iL&5%0CdJY'
    'odq#3#9L7Tj(NB@+<|$A;qWNj-PzrrvdM5KI@;S0w|Ap3-rbJ2w~wZ~yL;PvQ5f!zBKWtr8%_>KJNqo0?jH?VbcoN`=x7x0AB5p#'
    '_i!?t?8b2zAA|>Cyf-}DISPj%+lk`+$^PE{gl&h@>Cs^n?~M*7yOZ7M=y057%Q9b<K^~TKpr@SkB8D$T`6LBIqS?BUa(RC$1S?8`'
    'YVtMBV)mP`g}>_$ciPgIkbYLowqh>It$Tw-^w2X$6r+^duan<~Q#%E=ey$-QV&3i^NZ?=;0n-k5CVP7a;bi|{xHsJ!j=~{}V>X<|'
    'AdJ!IV0ajhCed~{*%|E*54MMsqtVXM-e@%1jSi;a_5q6eXtWncdu+7N4tAsAb~HKMkB<)7bnhtK52J(Ky~)w^@bHL@CUF$6lMrrV'
    '3rr}GmO*>6w*hi0mZG$!w7s+MZ6Cq^nt~E#Sn|ln86GNhEizML^f=|Sd6_(UA$pF6j;|G(HQTb4b(mK3fbdl=YK634C3&3o22Kyq'
    'M|1E#pyc2^(cLc7S(eQb7JHHMm|Ntsw#Y8L2~Xo0OMRLM+*}0>JPaqW7`X{g?HPbr^nLTWMJVQZ7<=<DjT2UEJW)I?CRyTTMa&9Z'
    '8^Z+1IeVS#DSwm>z<U4(?jaX9nj^Of(P9yn9?EQ^S(09mnkPbVheh@v;LB!HVUNp_C$9phnYT>8r=XYKLs+DMU%WcU614{!Ib)@l'
    '0V4|@v)5;<d6hJzjlDKaz#7Q!s8ZV~%)<$U`||14$pr)IO7H#<IGOU2{|<r&^GIh*Y{bqq6w32^5bmdZGa-cO6PXkQ^zc69$)?oW'
    'S_YO5s=l1?*HvvPP`O3P7GC}YGt)Py8M7<_9LRUJ*>om|){S7xr<{oh{LyA+GXs~9EdY|gfphg59v4{>mH-wru)u<Lwwb_j*@Q_k'
    'l)RpVPO)I%Q9+>sa67>=&BN$>P%xP{`uP(jrGEoi6sYQ3EWLN6Fh&r4did`~A#ebJBN0#{s*ymN$`~f7W#$lX>+BTb6%cuS>q|@+'
    '&!+Im34-aeTox<{9KOi2q6FNK>&hJ?lpZZ+5G4ew2Ik;H6F#ZF|0c2;I>}};@CeoSOjI9pU@ZExYCz1<-_&21lf1}aFZC4A%<40!'
    'XpS*Zk&iABsL-^3hObEUIK8>Pz6;JTZy;phpc_!+41&Io%u4Q=+XvAUEG@_B`Sri9K3$)l2WO{eA1`1=HF?V!_lS|>9(}IDa1=tw'
    'K{nproT+72P7+0gkiVQ>UIjN7pRb#+ZGA%UFL#%pZWZc!D!~K01cID>y1u#yZtqU-km$xP5K`+!0IqV83q_A!1%gYKGM@z3ll96S'
    'C{vpp2Ui5=2l@q$!V#Qei{iO(9_B2CydZT#;Yj-tK4cG1r2BIyw=mOnw+9X+6mGSxeqV{OD$leKUB~$WG#}O|j~(S>P9BO3!kL8d'
    '@=S14&~fU(&$&WynNG8T9Qp{#`3n~dw7rX>$O<)1c|uUFs75QhY(7vnY7T3v12FUj7?q+K0$G4c&x$t?kN-YhfB0~LGOjVWefbDH'
    'j}T69qlEY~B>^QoSJvfMBmHAZue5DB?2w8&a}E+hcM<b&mSzGXCP)mT16WeA;AxmZ9hzi?FdPG-y1BT$xC63aWV}5ZecdLd#3!U)'
    '!P)hv>l@?w@E@c73glm>H&>TeAG&}>70|`a&Gk(e$Z%1U5wj_{D5%)WAaDgsrUO*LfJi=eCXlT59q*sc6)3Xe0se?(j%@U+nd9D%'
    'ZUPccFm>*WW9LVA0Ujot!IyEbZ_I=x{GeI_2&+DuB*}zK5mc}UGQwl+^!!iR?1qMjG*EhjGCoB?gU||BP8*;>qND<l)EJ_~&tW21'
    '-<X0wQzhvb2%3(2(!xJp-W@y75{(a7e~~+K`!AZs`bY1Dc4x@1hGMYjnl&{;)xPDLeH$LOrf89z&YXXqR6HSJHx_77W@v;B$&$6m'
    'mAbu#-qOnE0<G<v(@n!rTWu-|nwZo|8x8oDWs#!Lp6T(+bH&$}XF@`jW{FJC(SVjaxc$!aFF9xx3m0doI9lwLSAfK$=@LFdeodKz'
    'c4e%1C!D;nb2sHOlw~v=0;xTr-bn4yG>=<b!Y*2e!ul+Y1v(`#)G&da#ZL}<glbv%4(>O{aHC20$zbsxIR}|mV+NxLaho0idu^)H'
    '!_J-bxV{<@rrRK<N?%MSs$kGY<uf!;#B8WO7eVDoPiWh&!h<TIG07oB1R<d;pAb<JE+%n!tSsK`8%RwDH11tpE1m7BHYDUzz_NP|'
    'VTD$48<uF01SlXPT;H5sR5+~p^-N=VT^B>?R7ahTKva?0@0c9Mu~bEOwa)gHB)g<&$QY6f_wSH_g5w4x&VMMSYl>N=$e4#X7@UzY'
    '_@5}V+<|zA>ObX$D4i*kRIpT~;L_CPj1%W8rYW#kpA-i^Aj5F+ZxT}J4~J~SrS-7(g@__hroi5D&;KpssjDz**3@~ekK0jC2Qno&'
    'xhs~;+A&)|UF>24b-Zr31O^+%<Q5XFrv)S)-v=o5n1i8}S@DG4ikI4+%ss;cnW2e5%>>(lsd^BRx@IV%2g_7K%3*TNdIGFz!OPU%'
    'FBTwqxfy$pPzzvks@9hM0J&YT4j5Xu^)pbWk`Wk|J9095B}9t;0*Yw4X>uMFHz4CLo|<gPRIZvxF1d)++=!M3jmu&D=qu8LGE>ys'
    '`)ieZF61M@>q1pkp7hNSfb05>a!;7xTwYx&p_iC`*Tvw%*B+aad1ZBm<9D=&6=0P@`uy0@eMRuNm!)1=AVOZ~0Dz@1fMVqbkHRU~'
    'w$7cy<R8e#Fs)fGg9)*lEDn){rNm`M9h4bqah4`e1fwQV)~d)x4Gw1^Pkob9D*v|%AAj*3)lk-Uf(&aQi3+mH&S*cnmP1R%`pGCG'
    '+^<?t-xRcDQ(X$cgy&j6TD2FLI%G^(GWo66Z9NSgOfWEj(bZUV`Sr7am$Ei6vJm%83-@cImRMf2suXMrI%aJUTrDfVqLzN61gg}N'
    '9_E0-K}Oo~y-`BB);<Oe7RfLQ9&4UG1VHl)mKUaU@CTHjkxez~w@ub)WT_L-{qIKJ`xvpjY}boe%QF1XAYc;KEYht7g7Yy#eBJ)m'
    'PKvE5Am1)tw^Pp|<WOoubSe3Q5lL<vh;(S&)0%5|3W$0<Nzhc$CV2`5%BAH($zW2{sud^|kbZ_XW<OQIPj!4D{+)9Xg+*K$yg>q0'
    'nXT1joHR*juuS{fH-h-MT!3osVzO;L!qFFO_mn(LAbspNbM%%(FneiIP-l}3XMj=_P};NDZMg}r3%eOw>~unMr-23iS6PH7&sM2;'
    'Og8vZ5!P&0Y-WI}e`RIV*cJj7M?8n6Kxl5GkX1DWJb|6(%TjuF2nbV%v6N>i4S)h8SKU(wyb=~PpdgbcM|PfaI}TG^!Hie67JV@f'
    'clP$R-<hh+1i5Y4g5BL4)DP+g8a2Jtioo7gATi6cGQa~c-L+i}I}^qsi3T&pDmUXV^BA%eN_|KRA?=Q`n7MYs+ycb_9Za4|CMrl('
    'K`G!ldyM&viPCLLPBP!kXBm1{WDKRvtMlb5Nx=DN$<lJ6vWuuaWHiztPk1Cre7K^Vm?UCnmBbT}qWda$`*NQpXtx$}mY`cT#QW}j'
    'tLUDk0WM7<ml=L*`0MuZ2*TEh?!F$6$LYH+q;=27!g}Hq<KCCE;QGtmxc9yT|LFKzjk0g1)6v|IGH}~2Y^Cq~?Zg?HVY0)k_r6p)'
    'TFoNGMS0W|{{y6d&)Eanmgam*E>$B-OF&Yi(rlz>@K(-Zxk*|OhzRluEZTu!Ec*(Uz~T__NdfA{)e3?50`lWh*Z3flEui-8Qt6Py'
    't|bYJ1Mh830x-|>oN#LvB^;7N^akVf{rmUM#2zwf`spXf8}5&WgMH^c{XTSl`l$iqnDr6Z977{f#1>gr(*I#`v}&H!PqI0CylPH+'
    'Jzd05^=UjBNaU0OuHv|CfUOaSy_8`cjY(^^h{~k+9AL%ZUy9ps%0673f-uRAx5e9EyMJj;8Yi8L_{yr9#;ID~^6<#NW7vxii>Gs4'
    '7rJt9C(Yv#5A+n1!BWpKtr^6slfde^*~LMEkXs06o!nRus$%Kebpc)SpipPVE<mDA9;)wlC~9_&RS6E(`?O<uWW+yEB+767R^cvZ'
    '*{4sMJ%PG=;g^rpx2`tX4PYR5^`a|+!b1U-j*JR4);H_$W$NO|5_@FPvc$ucdJj!Tc{%<z!XOQ1IM|W(%y_9HZry2;olG2b{$qwt'
    '$mf<xNqupvsZ$gB733oO`LN^}{>HA7UUuNn8sCicLbid(hYrk+WSlL_6Jwdrm!B_e0Lao!fb)xAufBZxG-!q<NwY802+Tn+Hf^_C'
    'w75+x<4_YNDGi3n%S26%$sV1-F9`<xYI3<IPl0gJJj+={mYm?njPfZeRRmbCSi+|nBvK6OlANJF(LE+BPpVHv%cXF;Y5u`kMhG#Z'
    'qfP<A8B$UP$t+8rkcN<_b}mbikIS2)jZ2}vMY+kjdY{;0Msk$Sc;HPUhy*;<1CTTnkl?e}LtPdpDYjt~{Z#(;<*#EG>RP<2+OPMZ'
    '-A)G|qAV@3Sz;&qHam=*Uy-4b6QL4?)Z;TCiQ&Zr4WY^aqSwk1V?LeQ>Hxj~#`JC`JOx)OzkR$oJ%7V4`??y^MA*w1{7!`Aq?P95'
    'DjB3%MSEDShWC!r7;4@o!0)XYjRC*$y?X;K%Oz$h!@%}zy|q`YWuvmnu0C)rqu#P|5y?V~N$MO(R*)4rzQ`dJbtiO`i&eHomw`yf'
    'Oh{O!LK$$!N@k6uG*!*kmoBz!yz4qgR3AzUL%&_4^Aj9(8!Z8wD_z8`gEtlf?-MLwgMOJQ72F+ANTExF;IJlq*6v7PLTHd^Ht0Kg'
    'MfT#vRaIufXDqR3rh%~ET#vf=jTKwnfBi$LlnD%#0mQyuF;TgadPbG!il!AdQRd6^J8Bd4HT7YbF_%bphub^5&fgvU1#uIVtJhzF'
    'wap7!qu*-xUEf}G^!8Ronzbc2d(0t$WU;QjORC|!O7ECQC7vw}lyl{2`R&+R=-G+}kP$3GZ1e0`PNSJ#A;d;0npJJ<plG2s$VRMY'
    '=44S|_J^c1LGZ4=(ZJ|4H)0L}gPIj=Nta~0nPwa#SBE3Ws)sp4CtZ00@Pu^gmnW<wpQI{h8J$Vr$~gcP?B7cep%sj5XCcCSkS56y'
    '90gvE@?|^CxNT)}QlEoK&2oPR@~^V;=WLnA^5&7m@!z-CSLfvF)Tq+Ie%pCd5?FbEI`I`e#i#>Syg}Z8RBAN>O_)+py`@)GwvIeu'
    '`eZIh<^Ol~L~RWy;FglHFfveIdD>Xd2jgB~6YCW!Q7%x5#VRinb`z-f_v7CA#phcqj+zh6Yj<?3P=5S$dV6>F@$~A$#mbqpe5rsR'
    '*rfh)e)_Mg;Ma?r+so^#m2;_nQ4?mV`T&|+f)<Cl`ksUk39xj7Ttr_1^XDDm9t9pIiEH~|tNq#J)@$6Iqq@qqbvmT;&tAdqJ$bX!'
    '$hH(Ukdn;Us+opIuyA1a-ByCH@0uRz-M5$jeSVgBUtWyV)Zl?hG~VDazJmJMq_v+n)fU_qJ+q@n7qhJ505{#J7Ahibz?Hd}Va^hi'
    'd}BKwv(V{2@tV4(Z$~6el(9r78?0q2_x-wk%F<;;#c;A_r3$uM%ZLWD)_*m28k~Kr8~X!lznKPDJTRadys0Fk2r&}*P6cx0n}G)E'
    '4$bOpBc~Wf@h*hCVMWbi;!WIoNs*XU@0X0Uwh%n<RiCZr-Kz7gt;(&uePg9oj-ajD4H{ZXC22O;rZv|L+wxMt#y142o?aC@O=NW5'
    'D3;SHe+2IP<sz^BrajT@XrXtcgdkona^b2#&hb6d@?>W~=ZFDBRCO5sGRC|AE70oBzCl&z{gW9>S-~T9MJ0&xC0W)$YDf1qT2$D?'
    ');hzs=vvw$jPT_+yiqoFYTWYJMZPuHqsFp?HT#}?!$h!|>05`Ttr}q5tMvRwQN52_$|L7C_+OGWH}ZjwCu`1b8_@l(dc?eUs?WV`'
    'fmcsg9sijyYaMQNr^~tx`^u_a*PLw5)~D(`<+lHyXJB>o%5(|Nd|9yOS#t$|=UM925g)W^&QoSM*BVUSkaQ~*MECx9xF6u>{(2`m'
    'MK3Crc}|D<@`V{f?U*DUJI~c}FO_lXVo^WoGDN+BK)++&G|8qFn!E4fl~xWdA}cGcU+vT>X!RPh8fd<ZtoO1Ry2ksWZ<~y7*s71@'
    '8~()PKnYr*`14Fq0m8iZxGq$5D52>B4V6Q>@f^@<VQs#_>XH3wa<9F>#vyK{1zT?@b^HYd>qMu+|7(joZr$A3cr8HT?eEgNo0wae'
    'i#9yeALMHXM<4&6`6>6f2}9f3^oL~EVyE(6FdC@$$}vTGr(W%T*V5~Egyx+L?C+$Q-@VwcfcFffn~0_9NsQ?eo+=a-Hma^0V6dY$'
    '*i>N_W$ZmyJABcOfKQC&^|zW46->QM)V+?x5WO95d!HLCnrp33`1)_0tXXSppl{x2Ub#bJzBO$X+6a_5TZdKwG|=j4>!_VB$_8R1'
    'v^OaSU@w<<Xgc>Gk#z{VMYtO8ltTAPN;aD?R)T81z({52|DO$OO}lX|{P>WXj7dUjN{8|*8Qhvm%d7bw&iB-Oy%|U{<)I#)zR24J'
    '4|5*jZ6HI`_<CFgxMAIk*W5p3PJJW5QGH(QkU5iO={$t;RCbC@SxgQ;pWc0}){Mi4G{78KC1+-BLs55SWH*W%FI>cR=+G!@;jL(9'
    'w&jRZ)kmwXnBgCSpf4?Y8*=S;(y*~_XuXy}M|G7{`h(W)Bz<;XPpuWY#v>DY{rb3nh3^<Zl+t3QQRGksaazol3n20{J#l08PCis*'
    'CqWQrQ4sXasd!Tt7os^<SJG>p(0V!;S`WgAkmCV-R<K}7eJ>LLNGMO#xrg;&&XW9u?!%e4Ue#ZKa?l*0c6737b+PiSdcoUn`@XuB'
    'S!*k*s9(2}5~SKiZ_)8*1X_Q_ie6rWCBmeB{p8JL=Pk0e)_S@G`l~k3Li{Jl4qIe{Tl=dBon+<QQPQLFzmW1eX|$+G(GY>0|7xi9'
    'G+ZXA*@ma<tjN2Zo=)(sJ4_h|qEA-T-fi|&N+;=d&OU!}TtybXqpd#nMZd`iRc$MNnBJy#Lip#|S}%jr)!7r<K~;_73Et@ms#lt%'
    'R}wx5AG@+HeK93R1FfRoI6pHd$d?HT+i_R1pu2PgR10z-XOZ)1U~aAa>Kg3^L}N9pUEO3ywdFT;1{*7E(jI)ZOGST}1phJsr7D5M'
    '83ZWtAgGEY`(Rh9gMC`74q*pYPBAdA^_>ALS^QaklP9)a?*^&HBvUzwe2s&?nU`4T;vz5IAq@6j{tt7pg7E'
))))
LOCK = {"schema": 1, "targetCpu": "arm64", "chromiumVersion": compat.VERSION,
        "chromiumCommit": compat.CHROMIUM_COMMIT,
        "macosPackaging": {"commit": compat.MACOS_COMMIT},
        "ungoogledChromium": {"commit": compat.COMMON_COMMIT},
        "officialToolchains": copy.deepcopy(compat._TOOLCHAINS),
        "rustArchive": {"url": compat._TOOLCHAINS["rust"]["url"],
                        "sha256": compat._TOOLCHAINS["rust"]["sha256"]}}
MACHO = bytes.fromhex("cffaedfe0c000001")


class RecipePolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.recipe = self.root / "recipe"
        for name, data in ORIGINALS.items():
            p = self.recipe / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data)

    def snapshot(self):
        return {name: (self.recipe / name).read_bytes() for name in ORIGINALS}

    def test_exact_approved_nine_patch_selection_and_resource_manifest(self):
        before = self.snapshot()
        result = compat.adapt_recipe(self.recipe, LOCK)
        self.assertEqual(len(result["retainedPatches"]), 9)
        self.assertEqual(len(result["omittedPatches"]), 14)
        self.assertEqual((self.recipe / "patches/series").read_bytes(), compat._series())
        self.assertEqual(result["originalSHA256"], compat._ORIGINAL)
        for name, expected in result["adaptedSHA256"].items():
            self.assertEqual(hashlib.sha256((self.recipe / name).read_bytes()).hexdigest(), expected)
        for patch_name in ("fix-build-without-crubit.patch", "fix-disable-verification-token.patch",
                           "revert-v8-sanitizer-changes.patch", "disable-clang-version-check.patch",
                           "fix-gn-compatibility.patch"):
            self.assertIn(patch_name, result["omittedPatches"])
        manifest = (self.recipe / "downloads-arm64.ini").read_text()
        self.assertIn(LOCK["officialToolchains"]["clang"]["sha256"], manifest)
        self.assertIn(LOCK["officialToolchains"]["rust"]["sha256"], manifest)
        self.assertIn(compat._NODE["sha512"], manifest)
        self.assertNotIn("rust-nightly", manifest)
        self.assertNotIn("strip_leading_dirs = rust", manifest)
        retriever = (self.recipe / "retrieve_and_unpack_resource.py").read_text()
        self.assertNotIn(compat._RUST_REWIRING, retriever)
        self.assertIn(compat._NEW_INSTALL_NAME, retriever)
        # No Node/Go setup or unrelated source code is altered.
        self.assertEqual(retriever, before["retrieve_and_unpack_resource.py"].decode().replace(
            compat._RUST_REWIRING, "", 1).replace(compat._OLD_INSTALL_NAME, compat._NEW_INSTALL_NAME, 1))
        compile(retriever, "guarded-retriever", "exec")

    def test_replay_and_each_changed_file_drift_are_refused_without_mutation(self):
        compat.adapt_recipe(self.recipe, LOCK)
        before = self.snapshot()
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "preimage"):
            compat.adapt_recipe(self.recipe, LOCK)
        self.assertEqual(self.snapshot(), before)
        for name in ORIGINALS:
            with self.subTest(name=name):
                for relative, data in ORIGINALS.items():
                    (self.recipe / relative).write_text(data)
                (self.recipe / name).write_text(ORIGINALS[name] + "# drift\n")
                before = self.snapshot()
                with self.assertRaisesRegex(compat.RecipeCompatibilityError, "preimage"):
                    compat.adapt_recipe(self.recipe, LOCK)
                self.assertEqual(self.snapshot(), before)

    def test_all_pins_including_object_hash_size_generation_and_deps_are_required(self):
        changes = [("schema", 2), ("chromiumVersion", "156.0.8078.48"),
                   ("chromiumCommit", "0" * 40), ("macosPackaging", {}),
                   ("ungoogledChromium", None), ("rustArchive", {})]
        for key, value in changes:
            lock = copy.deepcopy(LOCK)
            lock[key] = value
            with self.subTest(key=key), self.assertRaises(compat.RecipeCompatibilityError):
                compat.adapt_recipe(self.recipe, lock)
        for resource, fields in LOCK["officialToolchains"].items():
            for field in fields:
                lock = copy.deepcopy(LOCK)
                lock["officialToolchains"][resource][field] = "changed"
                with self.subTest(resource=resource, field=field), self.assertRaises(compat.RecipeCompatibilityError):
                    compat.adapt_recipe(self.recipe, lock)
        self.assertEqual(self.snapshot(), {k: v.encode() for k, v in ORIGINALS.items()})

    def test_symlink_recipe_parent_and_files_are_refused(self):
        link = self.root / "redirect"
        link.symlink_to(self.recipe, target_is_directory=True)
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.adapt_recipe(link, LOCK)
        parent = self.recipe / "patches"
        actual = self.recipe / "actual"
        parent.rename(actual)
        parent.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.adapt_recipe(self.recipe, LOCK)
        parent.unlink()
        actual.rename(parent)
        p = self.recipe / "downloads-arm64.ini"
        actual_file = self.root / "original.ini"
        p.rename(actual_file)
        p.symlink_to(actual_file)
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.adapt_recipe(self.recipe, LOCK)
        self.assertEqual(actual_file.read_text(), ORIGINALS[p.name])

    def test_hardlinks_vendor_checkout_and_started_source_tree_are_refused(self):
        p = self.recipe / "downloads-arm64.ini"
        other = self.root / "other.ini"
        os.link(p, other)
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.adapt_recipe(self.recipe, LOCK)
        other.unlink()
        for name in (".git", "build/src"):
            directory = self.recipe / name
            directory.mkdir(parents=True)
            with self.subTest(name=name), self.assertRaisesRegex(compat.RecipeCompatibilityError, "fresh isolated"):
                compat.adapt_recipe(self.recipe, LOCK)
            directory.rmdir()

    def test_install_name_alias_is_relative_and_never_replaces_unrelated_entry(self):
        llvm_bin_dir = self.root / "bin"
        llvm_bin_dir.mkdir()
        namespace = {"llvm_bin_dir": llvm_bin_dir, "os": os}
        code = textwrap.dedent(compat._NEW_INSTALL_NAME)
        exec(code, namespace)
        alias = llvm_bin_dir / "install_name_tool"
        self.assertEqual(os.readlink(alias), "llvm-install-name-tool")
        exec(code, namespace)
        alias.unlink()
        alias.write_text("unrelated")
        with self.assertRaisesRegex(RuntimeError, "Unexpected"):
            exec(code, namespace)
        self.assertEqual(alias.read_text(), "unrelated")

    def test_adapted_retriever_or_manifest_drift_blocks_before_subprocess(self):
        compat.adapt_recipe(self.recipe, LOCK)
        for name in ORIGINALS:
            p = self.recipe / name
            previous = p.read_bytes()
            p.write_bytes(previous + b"# drift")
            with self.subTest(name=name), patch.object(compat.subprocess, "run") as run:
                with self.assertRaisesRegex(compat.RecipeCompatibilityError, "drift"):
                    compat.prepare_platform(self.recipe, LOCK)
                run.assert_not_called()
            p.write_bytes(previous)


class InstalledPayload(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.recipe = self.root / "recipe"
        self.src = self.recipe / "build/src"
        self.cache = self.root / ".cache/source-downloads"
        self.cache.mkdir(parents=True)
        self.src.mkdir(parents=True)
        self.tools = copy.deepcopy(compat._TOOLCHAINS)
        self.original_node = copy.deepcopy(compat._NODE)
        self.patches = [patch.object(compat, "ROOT", self.root),
                        patch.object(compat, "_TOOLCHAINS", self.tools),
                        patch.object(compat, "_NODE", self.original_node)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        # The recipe is adapted before source retrieval begins.
        self.src.rmdir()
        for name, value in ORIGINALS.items():
            p = self.recipe / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(value)
        self.clang = self.src / self.tools["clang"]["outputPath"]
        self.rust = self.src / self.tools["rust"]["outputPath"]
        self.node = self.src / self.original_node["outputPath"]
        self.archive("clang", {"cr_build_revision": self.tools["clang"]["revision"].encode() + b"\n",
                              "bin/clang": MACHO + b"clang", "bin/llvm-objcopy": MACHO + b"objcopy"},
                     links={"bin/llvm-install-name-tool": "llvm-objcopy"})
        self.archive("rust", {"VERSION": compat._RUST_VERSION.encode(),
                             "bin/rustc": MACHO + b"rustc", "bin/bindgen": MACHO + b"bindgen",
                             "bin/cc_bindings_from_rs": MACHO + b"crubit",
                             "lib/third_party/crubit/BUILD.gn": b"crubit support",
                             "lib/libclang.dylib": b"libclang"})
        self.archive("llvmObjdump", {"bin/llvm-objdump": MACHO + b"objdump"})
        node_archive = self.cache / "node-v24.12.0-darwin-arm64.tar.xz"
        self.make_tar(node_archive, {self.original_node["strip"] + "/bin/node": MACHO + b"node"})
        self.original_node["sha512"] = hashlib.sha512(node_archive.read_bytes()).hexdigest()
        formatter = MACHO + b"formatter"
        formatter_cache = self.cache / compat._cache_name("clangFormat", self.tools["clangFormat"])
        formatter_cache.write_bytes(formatter)
        self.tools["clangFormat"]["sha256"] = hashlib.sha256(formatter).hexdigest()
        self.tools["clangFormat"]["size"] = len(formatter)
        self.tools["source"]["sha256"] = hashlib.sha256(b"fixture DEPS").hexdigest()
        self.lock = copy.deepcopy(LOCK)
        self.lock["officialToolchains"] = self.tools
        self.lock["rustArchive"] = {"url": self.tools["rust"]["url"], "sha256": self.tools["rust"]["sha256"]}
        compat.adapt_recipe(self.recipe, self.lock)
        self.src.mkdir()
        (self.src / "DEPS").write_bytes(b"fixture DEPS")
        (self.recipe / "build/download_cache").symlink_to(self.cache, target_is_directory=True)
        for key in ("clang", "rust", "llvmObjdump"):
            archive = self.cache / compat._cache_name(key, self.tools[key])
            output = self.src / self.tools[key]["outputPath"]
            output.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as tar:
                tar.extractall(output, filter="data")
        (self.clang / "bin/install_name_tool").symlink_to("llvm-install-name-tool")
        (self.node / "bin").mkdir(parents=True)
        (self.node / "bin/node").write_bytes(MACHO + b"node")
        (self.node / "bin/node").chmod(0o755)
        target = self.src / self.tools["clangFormat"]["outputPath"]
        target.parent.mkdir(parents=True)
        target.write_bytes(formatter)
        target.chmod(0o755)

    @staticmethod
    def make_tar(path, files, links=None):
        with tarfile.open(path, "w:xz") as tar:
            for name, value in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(value)
                member.mode = 0o755 if "/bin/" in "/" + name else 0o644
                tar.addfile(member, io.BytesIO(value))
            for name, value in (links or {}).items():
                member = tarfile.TarInfo(name)
                member.type = tarfile.SYMTYPE
                member.linkname = value
                tar.addfile(member)

    def archive(self, key, files, links=None):
        item = self.tools[key]
        path = self.cache / compat._cache_name(key, item)
        self.make_tar(path, files, links)
        item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        item["size"] = path.stat().st_size

    def test_complete_matching_layout_has_prebuilt_bindgen_and_crubit(self):
        result = compat.verify_platform(self.recipe, self.lock)
        self.assertTrue(result["prebuiltBindgen"])
        self.assertTrue(result["prebuiltCrubit"])
        self.assertIn("third_party/rust-toolchain/bin/cc_bindings_from_rs", result["requiredTools"])

    def test_every_installed_byte_stamp_and_unexpected_entry_is_checked(self):
        for relative in ("bin/clang", "cr_build_revision"):
            p = self.clang / relative
            previous = p.read_bytes()
            p.write_bytes(previous + b"tamper")
            with self.subTest(relative=relative), self.assertRaises(compat.RecipeCompatibilityError):
                compat.verify_platform(self.recipe, self.lock)
            p.write_bytes(previous)
        extra = self.rust / "untrusted"
        extra.write_text("extra")
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "entries"):
            compat.verify_platform(self.recipe, self.lock)

    def test_extra_installed_node_entry_is_rejected(self):
        (self.node / "unexpected.js").write_text("untrusted")
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "entries"):
            compat.verify_platform(self.recipe, self.lock)

    def test_missing_prebuilt_tools_never_trigger_a_source_rebuild(self):
        for name in ("bindgen", "cc_bindings_from_rs"):
            p = self.rust / "bin" / name
            previous = p.read_bytes()
            p.unlink()
            with self.subTest(name=name), patch.object(compat.subprocess, "run") as runner:
                with self.assertRaises(compat.RecipeCompatibilityError):
                    compat.verify_platform(self.recipe, self.lock)
                runner.assert_not_called()
            p.write_bytes(previous)
            p.chmod(0o755)

    def test_changed_cache_and_toolchain_symlinks_are_refused(self):
        p = self.cache / compat._cache_name("rust", self.tools["rust"])
        previous = p.read_bytes()
        p.write_bytes(previous + b"tamper")
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.verify_platform(self.recipe, self.lock)
        p.write_bytes(previous)
        binary = self.rust / "bin/bindgen"
        value = binary.read_bytes()
        target = self.root / "outside"
        target.write_bytes(value)
        binary.unlink()
        binary.symlink_to(target)
        with self.assertRaises(compat.RecipeCompatibilityError):
            compat.verify_platform(self.recipe, self.lock)
        self.assertEqual(target.read_bytes(), value)

    def test_prepare_uses_guarded_retriever_and_is_resumable_for_matching_outputs(self):
        with patch.object(compat.subprocess, "run") as runner:
            result = compat.prepare_platform(self.recipe, self.lock)
            self.assertTrue(result["prebuiltCrubit"])
            runner.assert_called_once()
            self.assertEqual(runner.call_args.args[0][-2:], ["-p", "arm64"])
        with patch.object(compat.subprocess, "run"):
            self.assertTrue(compat.prepare_platform(self.recipe, self.lock)["prebuiltBindgen"])

    def test_cache_redirection_and_failed_retrieval_do_not_run_verification_or_rebuild(self):
        cache = self.recipe / "build/download_cache"
        cache.unlink()
        other = self.root / "other"
        other.mkdir()
        cache.symlink_to(other)
        with patch.object(compat.subprocess, "run") as runner:
            with self.assertRaisesRegex(compat.RecipeCompatibilityError, "elsewhere"):
                compat.prepare_platform(self.recipe, self.lock)
            runner.assert_not_called()

    def test_formatter_substitution_is_preserved_and_rejected(self):
        target = self.src / self.tools["clangFormat"]["outputPath"]
        target.write_text("unrelated")
        with patch.object(compat.subprocess, "run"):
            with self.assertRaisesRegex(compat.RecipeCompatibilityError, "will not be replaced"):
                compat.prepare_platform(self.recipe, self.lock)
        self.assertEqual(target.read_text(), "unrelated")


class ResourceCache(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        root_patch = patch.object(compat, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.data = MACHO + b"formatter"
        self.item = {"url": "https://example.invalid/fixed-resource", "size": len(self.data),
                     "sha256": hashlib.sha256(self.data).hexdigest(), "generation": 42}

    def response(self, data=None, generation=42):
        result = io.BytesIO(self.data if data is None else data)
        result.status = 200
        result.headers = {"x-goog-generation": str(generation)}
        return result

    def test_generation_size_and_sha_are_checked_before_exclusive_cache_publication(self):
        with patch.object(compat, "urlopen", return_value=self.response()) as network:
            destination = compat._ensure_cache("clangFormat", self.item)
        self.assertEqual(destination.read_bytes(), self.data)
        self.assertEqual(destination.stat().st_nlink, 1)
        self.assertEqual(network.call_args.args[0], self.item["url"] + "?generation=42")
        with patch.object(compat, "urlopen") as network:
            self.assertEqual(compat._ensure_cache("clangFormat", self.item), destination)
            network.assert_not_called()

    def test_wrong_generation_corrupt_and_oversize_downloads_never_publish(self):
        for payload, generation in ((self.data, 43), (b"wrong", 42), (self.data + b"extra", 42)):
            with self.subTest(payload=payload, generation=generation):
                with patch.object(compat, "urlopen", return_value=self.response(payload, generation)):
                    with self.assertRaises(compat.RecipeCompatibilityError):
                        compat._ensure_cache("clangFormat", self.item)
                cache = self.root / ".cache/source-downloads"
                self.assertEqual(list(cache.iterdir()), [])

    def test_existing_cache_symlink_is_preserved_and_refused(self):
        cache = self.root / ".cache/source-downloads"
        cache.mkdir(parents=True)
        destination = cache / compat._cache_name("clangFormat", self.item)
        target = self.root / "unrelated"
        target.write_bytes(self.data)
        destination.symlink_to(target)
        with patch.object(compat, "urlopen") as network:
            with self.assertRaises((compat.RecipeCompatibilityError, OSError)):
                compat._ensure_cache("clangFormat", self.item)
            network.assert_not_called()
        self.assertEqual(target.read_bytes(), self.data)


if __name__ == "__main__":
    unittest.main()
