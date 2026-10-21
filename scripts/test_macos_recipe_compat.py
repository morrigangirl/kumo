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
import zipfile
import stat
import re

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
TYPESCRIPT_SOURCES = json.loads(zlib.decompress(base64.b85decode((
    'c-qxn|8v{6lK=hv6{z!4Nw1a^JI>b`-&|rlt$S(ei=CI7sWW^K2}y`afF(f7YMcN4b^%hNWRbEYkoPW=ktKZj>|(K4>;fS8=idm~'
    '(_@|lUQ81`?dxgGl%Mce_q7_y-bnDh*JSSzIg#-+;iIu8hffZlldCZ!C*wp$JdMbkRF7q%uEitrNiiaa1RxbrGEIC&d>JqTKS%PG'
    'C4vQHFeQ|{y*%wIJq;NNxz7Yt(_^ZMPX!q;L>kIe1cVDnXXO3)$=Qd?Gcx2M>s^a$!J}9vx_!OZ?+;QQ27N7M=#MEE{baz9?d!dc'
    'DL5qUu~gcViX0!4>%EYR^zM3({Ph<}74s4nNzK?D^E>3vYe9$?hg1(`5_thn$gD<}M#1x=>pfFszy(dFo}dvkCA9J}=Nn-mG~^!1'
    'h(dM-Kg;yv)aKG8Lf|Za6$4Peo0Y;M8JX(hb8f$F!}5fS8B6ymKyDx>YMo4aAXY;JJAx|3pvM9><e&uY1<=kuR5;}U5mG}RL%&-z'
    'P=bVHd>yy`{%7{}TPy2aR8fzMIMu*5`3?C%jVM#-+1Fk?z24hjQ~d7>EcR96_d`B_<U&gg$`@qCGrT|n4|TM_4kYyg=F5a?7$d!)'
    'r`3%1QeMbL)Ss>>BBLHvQ{i*X5;}k(u(HU?#EL4*2}~V6Ie6CdWf(GFb15o{B&;;EEPccTGYu^*QO;{tAV!0uD)aBArMU?kV#7-F'
    ')ifH&a9#F<h2f2mlQQW%@6jZo(;gRom<Fu0R9X5k4a3q*E_7Mu3rly94u>o$EfY}9$}>ySD_D9_&5|5^EtmL<o*L7H1reCwWLjQG'
    'CtQq5vvI@*rs=Ar%u73X*6H8Nbz>|mRhC{MrI%GwdbvieUxMO}*j-$b{VLP9vfQ%t3U*&rvHPmJQ(sm0*Q?4=cKD<>;3FVjnq98H'
    'm|2ou-c-meZz^PpG#ZqRCdjVrILKeG-&m+ZUYPwLvvYV*nqJZRgR0gatZCjsHRlJwGQ9ztTatfRrMHk<md=u-YzRYcMPm=E8hco&'
    ')sS5^1|hpr6i+Lg`gHA#3q{J(E86?Cs=Y_+XA3B^ma(JK^a{p~s%3q&M(>WQ`{L*!qwc7>!`3@NhtEpWhoPjpY=X!9a>+ca>axr~'
    'DxJU%*Z4<=&ng7BvN<c;AlRKQ*JqPkEj&}C%#Pd43U@g#!c{C)**tBFl%$s$5R+ThJ0`QNcTDCwwKIh@!@!l6qg1*xHZs8|=ziXW'
    '4JI<VfziCijhPp$$g=UZrKc(j-lJo}Aqblo^~Y@thW5!)aFoTB#pvw^h?lkr#t;vJ`7b8O+}p2O&L~EIW=-R}eyWl_M00&6Zb>`^'
    '!3tb?_%~bX7y@Ymak=dh5>q`UR6&Y|U-P99lFMh7pwa=@1D`21PnyoZONHRq0s?aKBhzn9P<sK0?au3Lp(2OuMbMQHwYNLCIM6an'
    '5v|vD`2low!i8Z4V&2wlsiKA1xVBJH4p$Fa$O9n>(`h2|M)d?x#V_qV;j83g_5(BkgYULy)XDQY`{W<lYDnwU&}qFU?E=Mp(gKZX'
    '!5>f>`~#ZZ>g;D#-sAcX)@T)0dRo<WKHC)#Q)^*0WMw^E2+8Vx`)wvw=nXIj?ar4@XWkVbQ*i~FdTBKEBb~JU$SSkiCrSr0)yE&C'
    'V78AS4;LDiy6+45fy`=Qu}lr1=v*gy7cyp|ZJT3|_K80Uj-`S?UBkC_XGXAC>-^%(q=OZ`m!5;Af`k4m8hV0FK&DI`UnMEn0VZIC'
    'z_feZO7*b&vem&FmPif?Oy-!rj3R*YVXA0%3QCga+n+e*_Lo3P#91lJN93KvF&qP|o)X9e!_>=0LaW=g=`FKF1w(ZPmFf5FH#A`W'
    '{Ri^fyy_RL>Z=%rO6xnmlQCng%y-A+Nk$s#oAstI_9v7Gp=T{{hy2H^oGsa-F?4*;zTUGXUS9)Sd%$T{VHpGoFMvEEKT#2YHS?)r'
    'icH2VVR<va_Q3?Fr_j~64DFdrM`L5wurr|=8B!RspldJ!=78*uMlm3cwT{*6et*REI31t@^ds&kQput2&!yAnN~KKopC3FcZ5gm#'
    'Y*{Y8<&x}<>*L1(6nkvs+L`s{Lk1S8Bn5v9`%d$SouOyZZk=RJy}oWeR`8Lv8Mt|@T0mzu=)jJUmNjhv3*)T?WwHchv(qW6y={e6'
    'ZRj4)EI@jmG0C16QLuHMwaSZ14`v4ZwbAWw2d}?$R!x!tyT#RW)rFZxXpoDUUbDGBUtV7|k$SfjWcmMmi(po)*Xs)|zS4f)sx><Z'
    'GcU%^R)o#6cc}+cm|JG<%La?^4<)lO85If57UP|4QaqHMnLn`H=H+dSjR02((QI^>orXu`Qp5P8NkHbq0CZ@OAiCLr;24}JA{Yxm'
    '+i;h`?gJ6r2ud-Nv_HN*BYlI$mF)D)AMn2X8#)5B2Qf;B{yxbZSS^Wyp@V->8#B1fNxl|^L8CI}j6WP`_3#ahRVs9EC4ckUCDGO{'
    'K&y5#Hpi>p_Sgz<cLYbwtl4bY9xrjknG=wbHTP}d+{%9CYRL{@cT+b|EBC3k1zWY;z9Ux2QuKDHmD^?8LOKDtzY?@9(*0$l?T{+A'
    '__hUf19ERMZ(Af+GJoMv=BpN~x5X-7BitHs#X9!3Sfy)^+W}VZyY7VPaw2%?2E>)>zI3L#FI~=Xt9PNd!&<pzy)Bdz5Lcb|%30^V'
    'a%gv6IkXb5+<6owyZzf@xdCxAm90E<uq~1!l`1*Tuq~E5+fsQ@VrxWK8o%}k#&)O&Za`dV*?}`HJ8-EP2M+tO<Uq=HV2948u;rsJ'
    '+k&jv*4`G%l~Nr#Q>sIEvth|uo^7$*>E}~-D)rRuy3+FbqisQ4>D5zbdUfPDqOLeIwJn|#5Lc2vaySl;Tuu~64hQv-b9dy(p_y>J'
    'W_<X}4amw<Z(D;oQrBnB3`N=DyKT`Ns{S)qs=vD??B4xlrwg}*ayVA*A1d4$#6^%<c~Wv~ypm&;+v2%#N=puAZj0o^CagK~xh>-A'
    '^PyX#Ia|;zJ9)Y>(1VVt?ttnFr{VzYE~vXV*Bp1qkJ%QE6%43ig`)(;0~KHFA(oYoyOtpQa7@-8S;)>?6bfpl-~)dzoodL>7<r-e'
    'DVk$1P8goSB0qotgbbJ$$si4x>i?&y-;bm}rhP5~c2|_vwm{jzjow!!#nw=Y3n^UiWPx_%$$)%S{UN<!T|9r5s0|_WgJ=&ywu~22'
    'x}cG}NdXUIxsay8aniv7V{w=L9=hOahP4}K_PJ>&(lwLmPMj@c-Q#T8s7z@xQjP|+!Rn7$7_&upWm_l*ePn^0sE&m)pALBH!dw7-'
    '<*bc4p1Y=YQ{jNe1*O=LI~Sc<Ev)6?5%A$~*U^C(II;U+Z+$6lVSx67DBe<@tI+PE&;gqHelIfH1q}TSS6DCwB-Gc74&Y9JO1XkU'
    '^>KxTPgA(UQVdUf`_Ayd#|<1{?P5-fIJ+5wMI`Ny`!tTjsS~~s%}?0UD!}G`+I>`1k1kZ<Vx*k0YOJ9%w1nZaK`!u&;dOwMY94N6'
    '*&fgx1~cFoIQgu*YVB|rW}!!D<gDrU*QPf`TRTz4X&f_%JCj{!%NbA?Pde{9#`6bX;zVlc%g{~ubRX8bP5IAm1g7NS65p1JIg#9@'
    'F|U~p#{8-&YFlclSqSU?p0Z@xRSZ{z<*vSP2_!m>E}2wg9y!H>!M?bEw|OT`*dR#o5zp>`2i)=KDFc_O?vI%0<AZMXus^5ZV0f-0'
    '0`X47mBPo6>LrxYt{-x6^}1s&bj`#dzdHz12C(>?c3q@4aS==4mnITiS!L>3m-8W8%IgjiIeGY~emK2Z61bMU|27xfS(Ju!dB>^_'
    'g3UC`QaQmVOYd~e#7<5xE}0orH4{2zx7=qR85mckFA^EWbvNyl(@>6TCUO?C2rPwtzPm|Um-o&T*FjO-@<a-xS~sOT2&@}W!*>t{'
    ')ZI@%U0q#dirxq%6~mNRccacR{-~P<UQ$pqjh`<Y8LJoQ)zwSlBcowdGmR^nj9A^>{+SIv-`k3=fzHmM)>;Y%NhWIcrAB(_<MrRd'
    '$FJb=odj|1q?+`$EXCU0ts)ulw}c7!nxj{<e`lyQ;^0|IR)7sqI%Oa~@b35@^=n77eyb%}x8rK4H08NkVt27rEO?iSMiiuOFV7HZ'
    '#?32`s@=~swCZ;B43P%BFhi$iH_Xte+Yd8DE*mp=wYz+VN)tYxA%q`w(=h3qc`LgR;bPQ~^I+1Oo7YYH2YSm#v@vpxjNXh=BXfmG'
    'Z^-2{>7SZ&W@q%8al}me^8HYC5W-F68fo}J+<)Wa4WN9$L$0Sa(|XIzd5XHJG#QW@g0;t^1u9L1ql@Hf9>7TKB#7%?<IBigBrKFP'
    'us0djPp*D@YX~(l6I(*JEUDLZMl#LD)`nu;p*0d|DzY}Ta@+R{70_XITZ^;&vd?DhMH9P13v{j$Dil7(R5QW47bs>lno)})sk2+Q'
    '^P!1{5xh!R-7;)ujb~1&_9Y%9Rrd;yp`j$$B^E%C9|ld*s$26KSh+$n@A;7VQ$J*%@d$A31NZ~e_`IbVyUm!4jAApyHdqGS96Mpz'
    '8#=Ql!PFSo+p=qJRqZQvb0W5z8Zqrff_3W!O!t2Mf$C>A_~qoHej>Fms3IM|)}3agfQuouDw&KTDf({`PX8NE`dWLQ)K78C$bJV>'
    'pcI$VzhSx&zt)mIxx8#vtS2-K2h_j$$VOc0WZD2lDTaKMCbcg*&B&p`{2FgEsq8?gsW@mx6#O^#3sb7*6^ERjyy2`)DW*!xsM#@a'
    '$_DAE2{O1~(*PYg5x9K!mW}BxmkkKeyojiQS;x3gXA#%B3AK2~Lv}KjQZ+&BN2Z%qdQ0ehvnK_2p!c5sF@2MaYBU{-K~eqgwxxP;'
    '`fjtiWfxk_s>sD<_7vB}E{~Z#h!SUs&l+xBo=`ujW*cU=ZO+Bl+IPS*ddyD~uBWF=(?)`iOGp6kiUkeqDO!qGRNX))rVY&ASM09g'
    'nc#{?Os4vhX}!U7{5uf*bopOwI*>F8-qWc}8*r2V$=ReChx{|;8nvZ<O8<i|iELI=?4SDSY;x1W4rFRRIKmov{wsUk4Ga3*SbSFJ'
    'hJkqywt)v!ce#^g4X~9_|INqqH)inUK2EKz$%vj@UT#QkOFHu)y2<8UY(sHNQger~(H7$MzKu{qH^3Ydc(C!<o=$V!HlMSa?6pP='
    'V@9jyIR#60VPfejrqj4)Lis}Ydzy-xw^0o_^Y&)e6t#CeVMBS>6gf+$#${+j<pX>)x^H2qUhtSTM=bw|ZLOOa#L|q3k9h5QP`{3d'
    '23lmU;2PHHT{nK6$zo=Wgc5ekRn1F%rhnexUFGN5<=vm^ol*?JQ#NEtQtK3H=$M^?_xy&{O{jr~B@LZlQeDH<KubjIJ<4@cS^aW{'
    'S}3i2?L!@unDAxIPg58=W3A&)8yvmZoB|gx72#R}4ZA$(u6)aF9W6^6us(Q0XB}g;_?iRUH8dZ!QZX0ug<W&|X!fmEddVG-!Vh<P'
    'SA<WKFs8WMD!Q=@r$ZiwtI`}2-{Fqcb$4|xUlM96ySZ!Lcvc%(>GeRHU7c8s2i}A?mhwh9K+9fUcmExByW#B)<d1m>iknD$R?h`q'
    'n5vx*8Y}?H2u4o!6k$KVq}K_n_85>OBuyW_b6$y+Ok*t_00pCjM(+9{;B+LU(%e^`Kc+&k&;^r1xk2e?FKcrGCpWmiv<irAa-5<H'
    'Xy^vSrI1FU9MD}iu2%uh--qRZOLQ?E!5limaUpyMZyd>RRP10yc{Sv0lg$C6Hq8N$U@n{k>7o;1S{u87Vad>$pW@CDh*L53AHFnK'
    '1!Zo>-suATB3i;|u)`ZVRzbP6t5C+p#Htu|f$}?eT`nXAy~k+e49Iv~X~dlPff=O3KFkm&Y~ThA6yL*zrof5IuOI$sX(bGIB>()a'
    'c<$t{LnkN+^_j;U9En{(RnL0Qw~7ZJ489mLWiNep@a~lRlxp$WEVP5`<Cj5S>@J!0BwV>>TD#yWO<YVS8!Ts5!Q8%d0pem7nNY>u'
    '=@!0FAsY#OI*^Hm*-0l3PQ8>7*=UVmLu?3s*`3eg-S>gYC^(CXi=acM{c%0~3VS`Atf?~<An*JbS~)m+B2I*D9`*I~7@b}hfPdgy'
    'm$!pSMZkUDwO}B-t&e*x0zLS$?n)StJHAgW=*Du_w<Rp#`qUq@E*BaP@x|L8I=c_*1jxR=MrpeB&|ZP(1Zl^IpO?Y#bfNj>1`i(%'
    'RSwmpuuj|EZJl-rR>dyv1z7;aGkLfqmcN+H)ktQWJX%?eWacWFCccyI-ei`l29ik>P)!|nhMh9H8+Y_WKxM*5Td$}u0FDp+t~=W>'
    'whw_gQI#>wi*AIrO9-(9G@C4(G%=F?%|@g2A$n&(eHw<{F-Ko$>Wou&dSc+*Srr54cqTWP8@L>mV8#MC0fI{IoC0Ufb35IjN4&wg'
    'tTk9VampIPjW>GMtrAcP8mqC??pWMmap4{g*G{YlL{K~k9U&=mtb7i(e4@rqk)FBH%Ut5+4LRUE>|D(-0f*FsU;U7cs6WmAbOCLH'
    '5jRK4m;v_isn-6Sw;dxs)1;}=EON0xhG>%n&w?zY8Q}uEG!3<<m4~md_aM-miSv5z?DFu*;nR$E_VcKBVOO6E$sh2t(fq21<@6I='
    '-7#lnmvi3WYT`;>0vRo_0x7fV@V&>g!^<nH<Ju*(JMpA_90Fke#H#kh6a3Oi$}k~S?31_=aw5*f2^#W$(u5-{RvFSznNmWYM{x+6'
    'sy{NFCI&A@nCIb}o)R9gh0J#_S?h5k)6w_@<g3ob<%9#BLLqh+vxM7|m#4EMvV{TwAt#qpp~nnDl~dbHpehqxEC!mOSaQqo${u|t'
    '(x{lJZg~8j4^GC+zgdR<xmeK05(_EdKl=t0Tn=CongRNLF7Wn}4>V%MqFmq>-=&EG7KMbDs{AU<>Fgp`rsOX)E~Ev_52?Mpsn`eD'
    'rBXq!7ZVF-R*T8tmt!AVK7Jj7zT(4EAMpq}6L_U@z!SEh2RK$fN@<VieaTbuU*E39-u~YR*()AhoW0rESOhc(D)AQ%H_i=L;cG9R'
    '?!6{^kG|`t3h$Q}7}=3{s>f11y%vwiiHxTZ0*p0*!S<Y7jTte|E%7uWZ&E0hC@l6#F(QWq=&4MM1UJ11{2bx^(1HbIFeQ|{y*vf4'
    'Vj406TFL}e(_^ZMPX!q;L>fvk!yrmXXXO3)$=Qd?GlFKLcP*f85s`{;qiqDY;R#ic;^Eh8k*9}LW0*BdQ0XAs9-k*o=ijBm0c(aV'
    '`H|_jT+n2SkM6ZQudN@<hcnP#MEx<SRl7ruk4cLr(etC$>)c(2-loZf3&RlfR|`saZ5dmHfl{m~9R;SeEtD|4viX+fHpBjFotk>B'
    '*Q8xQ*e5OM^cMU9V}*aT@>`w#Lbdl?q<2^gO2D^_*7|y%!C1?QGBqdmdqv$IyJNHZ-+r4(&Q2rk&X>G#v-!gebD8Q~5Lu7*zDh3I'
    '`41Q-0!Db-Gt;c+b@s_Wa`AL#{gjtxcVHk?do_tpp$igYL}&E`aEf2bYUaE@B5xFKWRnRaG-0T*6wFmNH1ayVycbu~m~-*a7Por6'
    '){4(L(89mge5ALE((23={$nbxppd;q<s+T6{m5DjwGR_i0Btz_AO*`M2Dxa4mWIg}nDA%yY{6{6LE-u6>s?6j4v<0_!}EXsBsi9;'
    'H)0yTwL9x8WXu++onM?is2<Feo7YPPzCK%llO@;$CmMBp1@?P=#rz?S<5sGN-IuLQcP;<>89yMmoE^Nr0f>Qz1x9B<pYjs+CmP)S'
    'C76<aUf0Phkbt4}sxlvj#`=GEOr8`*8lcQ)H2V)qhM*CaM2GyxLixN-kH+X!wy*bWx!2dws69}*tlBC#WM&22BVun4fe8oPA2J!k'
    '9Go{0<|-D&db&?=?GWZ4bd$_9ggpS&U`mH!80@1DvJA`aC^%k>m~(=!`~4Bu<8*+1*N?cLNF|55KbKyg<Et%H|M|hQHSL9l6x%x&'
    '^8M0a^7QfJ0E#{~@-Gy8@US)7MZurO-p2DC#z|_oPBIZ(U$-7B_{d}doIO@8^0-pz+bu9s#;^e~v|&&yOTY$nI*VFuTWK{HI@I&f'
    '26~>EZaohV_<CMG<HD5Ev*mjxtY|N)IcC#jbo<-E>n}*f`b{av=q~^ChKvGT2DV0U;|wi0JqIuUkDZ>}O@R*X_krIqz`cwiAN4_p'
    'H8Op@*QqFEo-+4L+WNxTyF6xJ*49uIL*GB}7|{Ids#+|6ZGy4@!;p@OUuSjDT%pg+Jm@(EZkF+T9ua(&JOX%Pv=s$!AE0k3^68vl'
    '?*jn>;mjDO<N?vl9}5}E5r=W!{^{zM_jn&k|L4n&g@Z9n6070_4`RZUjGKQXP7{3nr0PMpLq`S@sz(y61a6}e>@^$B5mPg>1doV{'
    '8TK|4Y{-E-D3^n`l|&x_Lmuqm0B_$UrroMz+yj|4%roi;!}L22Atx5IzQ!Z+8A2_vR7A@xrpeVUqA{?T;xRJ|*&`=Z2&sV+m}fBT'
    '2++u7IR9ECb&T=GzYGtytWEYT4bRdrB#tpO^}f<unk{|g`jK<^4!RJ_1V*lS9VfE%nGK+8?4pPba>6MwPCUd!H_#UF2Wfy^*^B9o'
    'E!eYw=Quo4w9z!MH>5*Qg$1nF&&5z0QVhItn-0Q(Mnh?aBME-}2r6O0X6Knn>mMGBbki`fByrF8TRDGLiZ}p`B=<pX9I!zLAWhiD'
    '(F`!}TcCnVh~VO6T;%Nk!l=+0OQvQ9j|(Ls`n@caF@}mn3Xn-VVZWy!AZTq?BzGV!99mw(RmUnga+&kc?V`B5rt2{Ji@HX*`J83d'
    '#YFjrH!Pg>GZywt;aRk5$(<Q($i;@CuN>xjACR9f!K!I<sL^x*C>0C3pxU;(t%j)i(8!N&g_&fDU%V0-2B%_nibZiCAha&i*9EoA'
    'd(lJ6p4tEY7fIs)l0eL%oOJH1@`^gMID4V3C{bY}t@-?sw>cqgtwyp_)L5+W^JN#8so=L@S;t@fdirbIPw<9aocoUspT2nc>dDcI'
    '&TI0KMKEgYbb%%hYQYd5rXeT*HXjXGfI4&gqL-}(dBxR6Iph3WHZ``hw&FwpdhIjxNXcJ+fzsMEP=G}8ppYb0W>6Qzl<nUXS1lIu'
    'g^o+}eEW8v6c-<<y0Ob$U_l4+ZeHh`34AT(Rpx!EC#)uA&&lS}{wZTJ#(61=rdKv%?u=;jegID@bRMqvAan)i2!yee4q^AobQ2_-'
    'oKi?Ty-H>48^f(`w2X7n&%?!a&HKP6<cbc+MM?8aAN+eY4WfJ7zBOHH+j}xo6oOX<DoDr`rI%M&8a~esUp#+u@a)x7Gkic`#-<vR'
    'X=P*V#S&i_1x#3uILQogwhBiI+6l6MlU0ewFoe}Au~)12y&kfXT9lB9OWMmt3u5|kb%6^#=&1ltR_?us;qtJ$Ncb%nu)=f%UgO-E'
    'B5y9vGq&w>v^kx55f7ga?qs}}4tqr2q9N{@`NMXOvF5&6+8QAdBV#jjfni_rP^|OPL$^d&WBrJXrP5}a^3x<?M&vT|$Kb3hvpj+t'
    'u4rVwB-x6I34x4FO;R-e+5C%eb93#@9{negLWddS7myT$oH%XFE$x#h&z>C~9z4osk^?lN_Y~^st5+|c9~~aN1cjOnNNBEU68PvW'
    'Ha!6Gn(EFbysW(j4hzG7!7%WKK*}iKY$*U_6o6CaXH~454^euMf~CKEenk4jECyzMjEGsu%=b4U${*!ku<@ny*(!U!a@xxW`ciLx'
    '|GnuvZ`NTr`m<gvBtkLtOHChq|9y_th9qN3GQ|fo)G5qQtDKFD-%MMV>Z9ytNcpst*`eaf3K+0eehhlP;H2`<?!{PE_Wt(mZ~qJN'
    '0O@u'
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

    def test_exact_approved_eight_patch_selection_and_resource_manifest(self):
        before = self.snapshot()
        result = compat.adapt_recipe(self.recipe, LOCK)
        self.assertEqual(len(result["retainedPatches"]), 8)
        self.assertEqual(len(result["omittedPatches"]), 15)
        self.assertEqual((self.recipe / "patches/series").read_bytes(), compat._series())
        self.assertEqual(result["originalSHA256"], compat._ORIGINAL)
        for name, expected in result["adaptedSHA256"].items():
            self.assertEqual(hashlib.sha256((self.recipe / name).read_bytes()).hexdigest(), expected)
        for patch_name in ("fix-build-without-crubit.patch", "fix-disable-verification-token.patch",
                           "revert-v8-sanitizer-changes.patch", "disable-clang-version-check.patch",
                           "fix-gn-compatibility.patch", "fix-typescript.patch"):
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
        self.deps = ("fixture DEPS\n'package': 'chromium/third_party/typescript/mac-arm64',\n"
                     "              'version': 'version:2@7.0.2'\n").encode()
        self.tools["source"]["sha256"] = hashlib.sha256(self.deps).hexdigest()
        self.ts_item = self.tools["typescript"]
        self.ts_files = {"lib/" + name: b"declare const value: string;\n" for name in re.findall(
            r'"(lib[^"/]*\.d\.ts)"', TYPESCRIPT_SOURCES["third_party/typescript/tsgo.gni"])}
        self.ts_files.update({"lib/tsc": MACHO + b"native TypeScript fixture",
                             "package.json": json.dumps({"version": "7.0.2", "name": "@typescript/typescript-darwin-arm64",
                                                          "os": ["darwin"], "cpu": ["arm64"]}).encode(),
                             ".cipdpkg/manifest.json": json.dumps({"format_version": "1.1", "package_name": self.ts_item["package"],
                                                                   "install_mode": "copy"}).encode()})
        self.ts_archive = self.cache / compat._cache_name("typescript", self.ts_item)
        self.make_zip(self.ts_archive, self.ts_files)
        self.ts_item["size"] = self.ts_archive.stat().st_size
        self.ts_item["sha256"] = hashlib.sha256(self.ts_archive.read_bytes()).hexdigest()
        self.ts_item["memberCount"] = len(self.ts_files)
        self.ts_item["unpackedSize"] = sum(map(len, self.ts_files.values()))
        self.lock = copy.deepcopy(LOCK)
        self.lock["officialToolchains"] = self.tools
        self.lock["rustArchive"] = {"url": self.tools["rust"]["url"], "sha256": self.tools["rust"]["sha256"]}
        compat.adapt_recipe(self.recipe, self.lock)
        self.src.mkdir()
        (self.src / "DEPS").write_bytes(self.deps)
        for name, value in TYPESCRIPT_SOURCES.items():
            path = self.src / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
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
        compat._install_typescript(self.src, self.ts_archive, self.ts_item)

    @staticmethod
    def make_zip(path, files, modes=None):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as contents:
            for name, data in files.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | (0o500 if name == "lib/tsc" else 0o400)) << 16
                if modes and name in modes:
                    info.external_attr = modes[name] << 16
                contents.writestr(info, data)

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


    def update_ts_zip(self, files=None, modes=None):
        self.make_zip(self.ts_archive, self.ts_files if files is None else files, modes=modes)
        with zipfile.ZipFile(self.ts_archive) as contents:
            infos = contents.infolist()
        self.ts_item.update(size=self.ts_archive.stat().st_size,
                            sha256=hashlib.sha256(self.ts_archive.read_bytes()).hexdigest(),
                            memberCount=len(infos), unpackedSize=sum(i.file_size for i in infos))

    def test_official_typescript_109_inputs_and_immutable_payload_are_required(self):
        result = compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        self.assertEqual(result["verifiedGNInputs"], 109)
        self.assertEqual(result["packageVersion"], "7.0.2")
        self.assertEqual(compat._install_typescript(self.src, self.ts_archive, self.ts_item), result)
        compiler = self.src / self.ts_item["outputPath"] / "lib/tsc"
        self.assertEqual(compiler.stat().st_mode & 0o777, 0o500)

    def test_missing_native_typescript_compiler_or_declared_library_is_rejected(self):
        for name in ("lib/tsc", "lib/lib.dom.d.ts"):
            files = dict(self.ts_files)
            del files[name]
            self.update_ts_zip(files)
            with self.subTest(name=name), self.assertRaisesRegex(compat.RecipeCompatibilityError, "declared GN"):
                compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_typescript_version_and_package_identity_cannot_drift(self):
        for metadata in ({"version": "7.0.1"}, {"version": "7.0.2", "name": "other"}, []):
            files = dict(self.ts_files)
            files["package.json"] = json.dumps(metadata).encode()
            self.update_ts_zip(files)
            with self.subTest(metadata=metadata), self.assertRaisesRegex(compat.RecipeCompatibilityError, "identity or version"):
                compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_typescript_zip_paths_duplicates_and_special_modes_are_rejected(self):
        for name in ("../escape", "/absolute", "lib/../escape", "lib\\evil", "./escape", "lib//escape"):
            files = dict(self.ts_files)
            files[name] = b"bad"
            self.update_ts_zip(files)
            with self.subTest(name=name), self.assertRaisesRegex(compat.RecipeCompatibilityError, "Unsafe"):
                compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        files = dict(self.ts_files)
        files["badXtail"] = b"bad"
        self.update_ts_zip(files)
        malformed = self.ts_archive.read_bytes().replace(b"badXtail", b"bad\x00tail")
        self.ts_archive.write_bytes(malformed)
        self.ts_item["sha256"] = hashlib.sha256(malformed).hexdigest()
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "Unsafe"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        for mode in (stat.S_IFREG | 0o777, stat.S_IFLNK | 0o500, stat.S_IFIFO | 0o400):
            self.update_ts_zip(modes={"lib/tsc": mode})
            with self.subTest(mode=mode), self.assertRaisesRegex(compat.RecipeCompatibilityError, "Unsafe"):
                compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        self.update_ts_zip()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.ts_archive, "a") as contents:
                info = zipfile.ZipInfo("lib/tsc")
                info.external_attr = (stat.S_IFREG | 0o500) << 16
                contents.writestr(info, MACHO)
        with zipfile.ZipFile(self.ts_archive) as contents:
            self.ts_item.update(size=self.ts_archive.stat().st_size,
                                sha256=hashlib.sha256(self.ts_archive.read_bytes()).hexdigest(),
                                memberCount=len(contents.infolist()),
                                unpackedSize=sum(i.file_size for i in contents.infolist()))
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "duplicate"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_typescript_zip_corruption_is_not_accepted_as_a_matching_resource(self):
        self.ts_archive.write_bytes(b"not a zip")
        self.ts_item.update(size=9, sha256=hashlib.sha256(b"not a zip").hexdigest())
        with self.assertRaises((compat.RecipeCompatibilityError, zipfile.BadZipFile)):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_typescript_extra_installed_files_and_wrong_modes_are_rejected(self):
        output = self.src / self.ts_item["outputPath"]
        extra = output / "untrusted.js"
        extra.write_text("untrusted")
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "entries"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        extra.unlink()
        (output / "lib/tsc").chmod(0o700)
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "mode"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_original_typescript_wrappers_default_and_deps_version_are_guarded(self):
        feature = self.src / "ui/webui/webui_features.gni"
        feature.write_text(feature.read_text().replace("use_typescript_go = true", "use_typescript_go = false"))
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "source policy"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)
        feature.write_text(TYPESCRIPT_SOURCES["ui/webui/webui_features.gni"])
        (self.src / "DEPS").write_bytes(self.deps.replace(b"version:2@7.0.2", b"version:2@7.0.3"))
        with self.assertRaisesRegex(compat.RecipeCompatibilityError, "DEPS TypeScript version"):
            compat._verify_typescript(self.src, self.ts_archive, self.ts_item)

    def test_typescript_install_never_replaces_an_unrelated_destination(self):
        output = self.src / self.ts_item["outputPath"]
        output.rename(self.root / "saved-typescript")
        output.mkdir()
        (output / "unrelated").write_text("keep")
        with self.assertRaises((compat.RecipeCompatibilityError, OSError)):
            compat._install_typescript(self.src, self.ts_archive, self.ts_item)
        self.assertEqual((output / "unrelated").read_text(), "keep")


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
