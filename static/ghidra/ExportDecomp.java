// Xuất mã giả C của các hàm theo tên hoặc địa chỉ. tools/flow.py dec dùng script này khi rea không hỗ trợ kiến trúc (MIPS…).
// Tham số: OUTFILE HÀM... ; "list:CHUỖI" liệt kê các hàm có tên chứa CHUỖI (kèm địa chỉ, kích thước).
//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        // một lượt duyệt FunctionManager cho mọi hàm cần tìm: trước đây quét lại cả chương trình mỗi tên (O(n*m))
        java.util.Map<String, Function> idx = new java.util.HashMap<>();
        for (Function g : currentProgram.getFunctionManager().getFunctions(true)) {
            idx.putIfAbsent(g.getName(true), g); idx.putIfAbsent(g.getName(), g);
        }
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                String q = a[i];
                if (q.startsWith("list:")) {
                    String sub = q.substring(5);
                    for (Function g : currentProgram.getFunctionManager().getFunctions(true))
                        if (g.getName(true).contains(sub))
                            w.println("// fn " + g.getName(true) + " @ " + g.getEntryPoint() + " size " + g.getBody().getNumAddresses());
                    continue;
                }
                Function f = idx.get(q);
                if (f == null) {
                    try { f = getFunctionContaining(toAddr(q)); } catch (Exception e) { f = null; }
                }
                if (f == null) { w.println("// ===== " + q + ": không tìm thấy"); continue; }
                DecompileResults r = di.decompileFunction(f, 180, monitor);
                w.println("// ===== " + q + " @ " + f.getEntryPoint());
                w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// lỗi: " + r.getErrorMessage());
            }
        }
        di.dispose();
    }
}
