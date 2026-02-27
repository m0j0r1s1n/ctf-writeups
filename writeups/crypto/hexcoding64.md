# Hackaboo HTB

The notorious CTF. I don’t think I’ll get much but If I get one flag I’m happy :). 

The first challenge I attempted was a very easy web but I’ll go back to that.

I did start a crypto challenge called **hexoding**. I downloaded the challenge file and was presented with a python file that appeared to output a .txt file:

```bash
m0j0@r1s1n: ~/ctf/hackaboo/crypto_hexoding64
$ cat output.txt                                                                                                                            [5:09:31]
4854427b6b6e3077316e675f6830775f74305f3164336e743166795f336e633064316e675f736368336d33735f31735f6372756331346c5f6630725f615f
Y3J5cHQwZ3I0cGgzcl9fXzRsczBfZDBfbjB0X2MwbmZ1czNfZW5jMGQxbmdfdzF0aF9lbmNyeXA1MTBuIX0=%
```

It look liked Base64 at first but I had the challenge name in my head. Anyway CyberChef at the reaady:

```bash
ãÎxãnÛé¾ßNûß^ë¾_ëÍôï¾_ïôåýõë÷éîøß^ºïÞ_ß~ë}ôëõéî»åþ÷ë~¼ß~ß~÷åýõï~_ë~öï·ß]øéÎ_ë­ôïn_ë^_crypt0gr4ph3r___4ls0_d0_n0t_c0nfus3_enc0d1ng_w1th_encryp510n!}
```

I get a partial flag so I took what wasn't decoded and put it in decode.fr. It is ASCII code.

```bash
/2	HTB{kn0w1ng_h0w_t0_1d3nt1fy_3nc0d1ng_sch3m3s_1s_cruc14l_f0r_a
```

Now the 2 combined is:

```bash
HTB{kn0w1ng_h0w_t0_1d3nt1fy_3nc0d1ng_sch3m3s_1s_cruc14l_f0r_a_crypt0gr4ph3r___4ls0_d0_n0t_c0nfus3_enc0d1ng_w1th_encryp510n!} [5:09:36]
```

Boom it was correct.
