// Đặt tên hàm theo file "0xaddr tên" (do tools/static/gopclntab.py sinh ra), tạo hàm nếu Ghidra chưa nhận ra.
// Dùng cho Go bị strip trên kiến trúc mà Ghidra không tự khôi phục tên (MIPS…). Tham số: NAMESFILE
//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ApplyNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        int named = 0, created = 0;
        for (String line : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
            String[] p = line.trim().split(" ", 2);
            if (p.length < 2) continue;
            Address a = toAddr(p[0]);
            String name = p[1].replaceAll("[^A-Za-z0-9_.$*()\\[\\]/-]", "_");
            Function f = getFunctionAt(a);
            if (f == null) {
                disassemble(a);
                f = createFunction(a, name);
                if (f != null) created++;
            }
            if (f != null && !f.getName().equals(name)) {
                try { f.setName(name, SourceType.IMPORTED); named++; } catch (Exception e) { }
            }
        }
        println("ApplyNames: đặt tên " + named + ", tạo mới " + created);
    }
}
