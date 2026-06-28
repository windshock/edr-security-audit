import os
eicar_str = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
with open('/tmp/eicar.com', 'w') as f:
    f.write(eicar_str)
print("EICAR file written successfully to /tmp/eicar.com")
