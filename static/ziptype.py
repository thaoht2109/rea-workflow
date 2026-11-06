# Nhận dạng ZIP chính là mẫu (APK, OOXML, JAR, ODF) để flow.py new giữ nguyên thay vì giải nén. Chỉ đọc danh mục file trong ZIP,
# không giải nén, không phụ thuộc pefile (flow.py nạp được trước khi kiểm công cụ).
import zipfile

ZIP_KEEP = {'AndroidManifest.xml': 'APK', 'classes.dex': 'APK', '[Content_Types].xml': 'Office OOXML', 'META-INF/MANIFEST.MF': 'JAR', 'mimetype': 'ODF/EPUB'}

def zip_kind(s):
    """Tên loại nếu ZIP là chính mẫu, không thì None (ZIP thường, hỏng, hoặc không phải ZIP)."""
    try:
        with zipfile.ZipFile(s) as z: names = set(z.namelist())
    except (zipfile.BadZipFile, OSError, ValueError): return None
    return next((v for k, v in ZIP_KEEP.items() if k in names), None)
