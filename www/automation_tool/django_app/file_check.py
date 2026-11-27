from .lib_tool.PA_tool import read_sheet
from .security import target_ip_error
from . import template_spec as spec
import openpyxl

# Strict structure check of uploaded Excel: the file must follow the template (template_spec.py, FEAT-23: one template,
# add + edit sheets), anything wrong -> reject the whole file

#columns of old templates -> what replaced them (file of an old template: say which template to use, BUG-70)
OLD_COLUMNS = {
    'index': "was replaced by 'Position' + 'Reference-rule'",
}


#allowed columns of each sheet = columns of the template (single source of truth: template_spec.py)
def allowed_columns():
    return {sheet: [c['name'] for c in spec.sheet_columns(sheet)] for sheet in spec.SHEET_ORDER}


def _norm(name):
    return str(name).strip().lower()


#user value echoed in an error message: shortened (escaping is done by the template)
def _short(value, limit=60):
    text = str(value)
    return text if len(text) <= limit else text[:limit] + '...'


#example row of the template (Device-ip hint not replaced)
def _is_example(value):
    text = str(value).strip()
    return text.startswith('<') or text.upper().startswith('EXAMPLE') or text.startswith('[Required]')


INVISIBLE = '\u200b\u200c\u200d\u2060\ufeff'      # zero-width characters, BOM: not removed by strip()
# exact spellings left by export tools (pandas / Python / SQL); lowercase 'none' is a valid value (NAT translation type)
EXPORT_LEFTOVERS = ('nan', 'NaN', 'None', 'null', 'NULL')
EXCEL_ERRORS = ('#N/A', '#REF!', '#VALUE!', '#DIV/0!', '#NAME?', '#NUM!', '#NULL!', '#SPILL!', '#CALC!')


#cell that looks empty or correct in Excel but is not (the Guide lists the cases): the message only gives its position
def cell_invalid(cell):
    if cell.data_type == 'f':
        return True                                    # formula: never evaluated by the tool, its result may be missing or stale
    value = cell.value
    if not isinstance(value, str) or value == '':
        return False                                   # number, date, empty cell
    text = value.strip()
    return (text == ''                                 # only spaces
            or any(c in value for c in INVISIBLE)      # zero-width characters, alone or inside a value
            or text in EXPORT_LEFTOVERS
            or text.upper() in EXCEL_ERRORS)


#return list of error messages (empty = structure OK)
def check_structure(file, sheet_list):
    allowed = allowed_columns()
    errors = []
    book = openpyxl.load_workbook(file)     # formulas kept as formulas (not their cached result)
    if hasattr(file, 'seek'):
        file.seek(0)
    for sheet in sheet_list:
        if str(sheet).strip().lower().startswith('delete_'):
            errors.append(f"Sheet '{_short(sheet)}' is not supported: delete on the firewall by hand")
            continue
        if sheet not in allowed:
            hint = [k for k in allowed if _norm(k) == _norm(sheet)]
            errors.append(f"Unknown sheet '{_short(sheet)}'" + (f" — did you mean '{hint[0]}'?" if hint else '') +
                          ' (sheet names must match the templates exactly)')
            continue
        df = read_sheet(file, sheet)
        header = list(df.columns)
        for col in header:
            if str(col).startswith('Unnamed:'):
                if df[col].notna().any():
                    errors.append(f"Sheet '{sheet}': a column without header contains data")
                continue
            if col not in allowed[sheet]:
                hint = [k for k in allowed[sheet] if _norm(k) == _norm(col)]
                if _norm(col) in OLD_COLUMNS:
                    errors.append(f"Sheet '{sheet}': column '{_short(col)}' is from an old template, it {OLD_COLUMNS[_norm(col)]} — "
                                  "download the current template on the Configure page")
                    continue
                errors.append(f"Sheet '{sheet}': unknown column '{_short(col)}'" + (f" — did you mean '{hint[0]}'?" if hint else ''))
        for col in spec.mandatory(sheet):
            if col not in header:
                errors.append(f"Sheet '{sheet}': missing mandatory column '{col}'")
        #edit rule / group sheet: every editable column of the file needs its mode column and the other way round
        if sheet in spec.MODE_SHEETS:
            for col in spec.editable(sheet):
                if col in header and spec.mode_name(col) not in header:
                    errors.append(f"Sheet '{sheet}': column '{col}' needs its mode column '{spec.mode_name(col)}'")
                elif col not in header and spec.mode_name(col) in header:
                    errors.append(f"Sheet '{sheet}': column '{spec.mode_name(col)}' without column '{col}'")
        if 'Device-ip' not in header:
            continue

        # rows (Excel row number = index + 2): example row, Device-ip empty / not a valid IPv4 address
        if df.empty:
            errors.append(f"Sheet '{sheet}': no data row (delete the sheet if it is not used)")
            continue
        ws = book[sheet]
        ip_col = header.index('Device-ip') + 1
        rows = []                                          # (Excel row, message): sorted by row at the end (BUG-53)
        for index, value in df['Device-ip'].items():
            row = index + 2
            if df.loc[index].isna().all():
                continue                                   # fully empty row
            cell = ws.cell(row=row, column=ip_col)
            if cell_invalid(cell) and not (isinstance(cell.value, str) and cell.value.strip() == ''):
                continue                                   # formula / Excel error (pandas reads it as empty): 1 'invalid value' line below
            if isinstance(value, float) or str(value).strip() == '':
                rows.append((row, f"Sheet '{sheet}' row {row}: Device-ip is empty"))
            elif _is_example(value):
                rows.append((row, f"Sheet '{sheet}' row {row}: this is the example row of the template, replace it with real values or delete it"))
            else:
                problem = target_ip_error(value)
                if problem:
                    rows.append((row, f"Sheet '{sheet}' row {row}: Device-ip '{_short(value)}': {problem}"))
            if sheet not in spec.SHARED_SHEETS and 'Vsys' in header and str(df.loc[index, 'Vsys']).strip().lower() == 'shared':
                rows.append((row, f"Sheet '{sheet}' row {row}: Vsys 'shared': a rule is always in a vsys, only objects can be in shared"))

        # cells read with openpyxl as typed (pandas turns Excel errors into the text 'nan');
        # formulas in every column, other cases in data rows only (Device-ip: formula / Excel error only, its value is checked above)
        data_rows = set(df.index + 2)
        clear_cols = spec.clearable(sheet)
        for cells in ws.iter_rows(min_row=2, max_col=len(header)):
            for col, cell in zip(header, cells):
                if cell.data_type != 'f' and (cell.row not in data_rows or col not in allowed[sheet]):
                    continue
                if col == 'Device-ip' and isinstance(cell.value, str) and cell.value.strip() == '' and cell.data_type != 'f':
                    continue                                   # only spaces = 'Device-ip is empty' above
                if col in clear_cols and cell.data_type != 'f' and str(cell.value).strip().lower() == 'none':
                    continue                                   # edit sheet: none / None / NONE clears this value (FEAT-23)
                if cell_invalid(cell):
                    rows.append((cell.row, f"Sheet '{sheet}' row {cell.row}, column '{col}': invalid value, check this cell"))
        errors += [msg for _, msg in sorted(rows, key=lambda r: r[0])]
    return errors[:50] + ([f'... and {len(errors) - 50} more problem(s)'] if len(errors) > 50 else [])
