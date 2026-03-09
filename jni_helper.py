import idaapi
import idautils
import idc
import ida_name
import ida_typeinf

def apply_cdecl(ea, decl):
    parsed = ida_typeinf.idc_parse_decl(None, decl, ida_typeinf.PT_SIL)
    if parsed is not None:
        ida_typeinf.apply_type(None, parsed[1], parsed[2], ea, 1)
        return True
    return False

def fix_jni():
    print("==============================================================")
    print("       JNI Helper for IDA 8/9 (Python 3)                      ")
    print("==============================================================")
    
    count = 0
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue
            
        if name.startswith("Java_"):
            # Set basic JNI static method signature
            # This turns a1 into JNIEnv* and a2 into jobject/jclass
            decl = "int __fastcall {}(JNIEnv *env, jobject thiz);".format(name)
            if apply_cdecl(ea, decl):
                print("[+] Repaired: {}".format(name))
                count += 1
        elif "JNI_OnLoad" in name:
            decl = "int __fastcall {}(JavaVM *vm, void *reserved);".format(name)
            if apply_cdecl(ea, decl):
                print("[+] Repaired: {}".format(name))
                count += 1
        elif "JNI_OnUnload" in name:
            decl = "void __fastcall {}(JavaVM *vm, void *reserved);".format(name)
            if apply_cdecl(ea, decl):
                print("[+] Repaired: {}".format(name))
                count += 1
    
    print("==============================================================")
    print("[+] Done! Fixed {} JNI functions.".format(count))

if __name__ == '__main__':
    fix_jni()
