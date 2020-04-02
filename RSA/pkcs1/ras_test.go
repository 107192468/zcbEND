package RSA

import "testing"

func TestRSASecurity_PubKeyDECRYPT(t *testing.T) {
	pub := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzRyubPwEJNr4wW3t58+UkWjOp0q2RdqcTOE9qVOeQjpmuHn4FEbb5+rw+ra2tlQIx//Cr6/0xmccokdrMOT21xV+FvtAWOusl1GV6XO7RWqsM5PkvIBuroJcEiUw6puRvbpEhfyjaovn7HoMfG1JFUy74+DPTuxp7MhSktMknzwIDAQAB"
	pri := "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALNHK5s/AQk2vjBbe3nz5SRaM6nSrZF2pxM4T2pU55COma4efgURtvn6vD6tra2VAjH/8Kvr/TGZxyiR2sw5PbXFX4W+0BY66yXUZXpc7tFaqwzk+S8gG6uglwSJTDqm5G9ukSF/KNqi+fsegx8bUkVTLvj4M9O7GnsyFKS0ySfPAgMBAAECgYBYWLI8hwfTqo5+9hYbOv2otGrRPWkbTgV3i0BXfg+/RQamr5Aan2g0OEOb/6qe59d1HFNV5a2YS9fBPl88VNj7bmGx3x6r8E0yq13zqcItHVNhAO0+LwgSMOA94Azl6D4K8CHKN6ZXnpISLAnpm3K1cOtZRFoMxlALMiSHSQpqQQJBAOyKNvB+cINqMJ0F9WMxyppG+xwGkV7DRbDHqYrWEtIKmtZZemX6ghR4U3qLPxEI6OHbY6wNkDiKBLGKzs2NGnUCQQDCBvVi9Ki0k+Ua1Qg+XmwnTpXnhuJFcwWq7HjcAY3zIZbYKgAOVTlhuSK9roZEh3/McgEaR7ywsOsqXJxHnAizAkEAwPVHOAyNEEcR/SYdNZwqoIwC0Kvy7pDxSvK1tdJIbBvGj9FSbdpbPwOhZbgt7GGOSKDFwFcYLWc5yPNpHHlc+QJADldNU98ZiR9VU8JjNZjtDYq1ccN6ff+eb5/C3yAOSeY1rAyOrICIGT0B4FtB+Va6j3Xttu+OdtDc0Oi/dFuIGQJBAJeEhd2EalO+2fJQ2qDdaMwvudrW4wmxHVxRZNI5WxkZ0fWiSRspYamTLcW89l03mLQhjja/GIxTic9YdvsyXLo=" +
		"XKn6t/kMyYNCvNqknVlCoPVXMEsBFCE0IWaQwPLyhiydEKZYtR8b4a7wN7jmijzERBL1zpYB6lQWH7owgTOfNGDcaTSNUVO9C9djZxgCLPj6ZUm9OkFhkYochRTOrJ9sSMjl/VUx00bMw27ZIB3WNMGyQtrgveTd7O5GDCGIgLA="

	data := "世界真美好！"
	bbyte, err := PublicEncrypt(data, pub)
	if err != nil {
		panic(err)
	}
	dbyte, err := PriKeyDecrypt(bbyte, pri)
	if err != nil {
		panic(err)
	}
	t.Log(string(dbyte))

}
