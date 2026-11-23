#!/usr/bin/env python3
# Theo dõi giá trị thanh ghi tối thiểu cho MIPS o32 PIC (gp-relative): gp từ prologue (lui/addiu gp + addu gp,gp,t9), lw reg, off($gp) đọc ô GOT trong file,
# addiu/ori/move lan truyền hằng, jalr $t9 -> đích. Giải lời gọi qua GOT và chuỗi nạp theo gp mà disasm thẳng không thấy. Chỉ đọc file.
# Không có đồ thị luồng: chỉ đúng trên đoạn chạy thẳng. Nơi dùng phải xóa `regs` ở mọi đích nhánh (điểm hợp lưu); lớp này tự bỏ thanh ghi sau lời gọi và sau jr/j/b.
import re, struct

# Mặc định an toàn: MỌI lệnh có toán hạng đầu là thanh ghi đều coi như ghi vào thanh ghi đó và làm mất giá trị đã biết, trừ các lệnh chắc chắn không ghi
# (store, nhánh/nhảy, trap) và vài lệnh đã mô hình hóa bên dưới (lui, addiu, ori, move, lw, addu gp). Lệnh lạ chỉ làm mất chú thích, không sinh chú thích sai.
NOWRITE = {'sw', 'sh', 'sb', 'swl', 'swr', 'sd', 'sdl', 'sdr', 'swc1', 'sdc1', 'swc2', 'sdc2', 'swxc1', 'sdxc1', 'suxc1', 'cache', 'pref', 'sync', 'nop', 'ssnop', 'ehb',
           'teq', 'tne', 'tge', 'tgeu', 'tlt', 'tltu', 'teqi', 'tnei', 'tgei', 'tgeiu', 'tlti', 'tltiu', 'syscall', 'break', 'mthi', 'mtlo', 'mtc0', 'mtc1', 'mthc1', 'ctc1',
           'mult', 'multu', 'madd', 'maddu', 'msub', 'msubu'}   # `sc` KHÔNG ở đây: nó ghi kết quả vào rt; `div/divu` in toán hạng đầu là $zero
_INT = lambda s: int(s, 0)

class Tracker:
    def __init__(self, d, I, got_va=None):
        self.d, self.I, self.E = d, I, '>' if I['be'] else '<'; self.regs = {}; self.gp = None; self.hi = None; self.lui_at = None; self.got = got_va; self.pending = None   # pending: 'call' | 'ret' = xử lý sau delay slot

    def _u32(self, va):
        from static import elfinfo
        o = elfinfo.va2off(self.I, va)
        return struct.unpack_from(self.E + 'I', self.d, o)[0] if o is not None and o + 4 <= len(self.d) else None

    def step(self, i, entry=None):
        """Cập nhật theo lệnh i. Trả địa chỉ đích nếu là jalr $t9/jr $t9 đã biết giá trị, ngược lại None."""
        m, ops = i.mnemonic, [x.strip() for x in i.op_str.split(',')]
        pend, self.pending = self.pending, None   # pend: lệnh này là delay slot của lời gọi/return trước nó: chạy bình thường rồi áp hiệu ứng
        r = self._step(i, m, ops, entry)
        if pend: self._clobber(pend)
        return r

    def _clobber(self, kind):
        """Sau lời gọi: thanh ghi caller-saved không còn tin được; sau jr/j/b: đoạn kế không nối tiếp, bỏ hết (giữ gp: hàm sau tự đặt lại ở prologue)."""
        if kind == 'ret': self.regs.clear(); return
        for r in ('$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3', *(f'$t{n}' for n in range(10))): self.regs.pop(r, None)

    def _step(self, i, m, ops, entry):
        R = self.regs
        if m in ('jalr', 'jal', 'bal', 'bgezal', 'bltzal'): self.pending = 'call'
        elif m in ('jr', 'j', 'b'): self.pending = 'ret'   # return, tail-call hoặc nhảy vô điều kiện: lệnh sau delay slot không tới được bằng chạy thẳng
        if m in ('jalr', 'jr') and ops and ops[-1] == '$t9': return R.get('$t9')
        if not ops or not ops[0].startswith('$') or m in NOWRITE or m.startswith('j') or (m.startswith('b') and m not in ('bitswap', 'bitrev')): return None   # không ghi thanh ghi (nhánh/nhảy: `jal`/`jalr` đã đặt pending ở trên)
        dst = ops[0]; val = None
        if m == 'lui' and len(ops) == 2 and re.fullmatch(r'(0x)?[0-9a-f]+', ops[1]):
            val = (_INT(ops[1]) << 16) & 0xffffffff
            if dst == '$gp': self.hi = val; self.gp = None; self.lui_at = i.address   # prologue PIC: lui gp ở đầu hàm = địa chỉ vào hàm
        elif m == 'addiu' and len(ops) == 3:
            imm = _INT(ops[2]) if re.fullmatch(r'-?(0x)?[0-9a-f]+', ops[2]) else None
            if ops[1] == '$zero' and imm is not None: val = imm & 0xffffffff
            elif ops[1] in R and R[ops[1]] is not None and imm is not None: val = (R[ops[1]] + imm) & 0xffffffff
            if dst == '$gp' and ops[1] == '$gp' and self.hi is not None and imm is not None: self.hi = (self.hi + imm) & 0xffffffff; val = None   # gp0 = hi + lo, chờ addu gp,gp,t9
        elif m == 'ori' and len(ops) == 3 and ops[1] in R and R[ops[1]] is not None and re.fullmatch(r'(0x)?[0-9a-f]+', ops[2]): val = R[ops[1]] | _INT(ops[2])
        elif m == 'move' and len(ops) == 2: val = R.get(ops[1]) if ops[1] != '$zero' else 0
        elif m == 'addu' and dst == '$gp' and ops[1:] == ['$gp', '$t9'] and self.hi is not None and (entry is not None or self.lui_at is not None):
            self.gp = (self.hi + (entry if entry is not None else self.lui_at)) & 0xffffffff; val = None   # t9 = địa chỉ vào hàm khi gọi qua GOT
        elif m == 'lw' and len(ops) == 2:
            mm = re.fullmatch(r'(-?(?:0x)?[0-9a-f]+)\((\$\w+)\)', ops[1])
            if mm and mm.group(2) == '$gp' and self.gp is not None: val = self._u32((self.gp + _INT(mm.group(1))) & 0xffffffff)
            elif mm and mm.group(2) in R and R[mm.group(2)] is not None: val = self._u32((R[mm.group(2)] + _INT(mm.group(1))) & 0xffffffff)
        if dst != '$gp': R[dst] = val
        return None
