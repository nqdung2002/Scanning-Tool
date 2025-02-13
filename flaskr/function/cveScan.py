from packaging.version import Version

v1 = Version(input("Nhập phiên bản: "))
v2 = Version("1.0")

print(v1==v2)