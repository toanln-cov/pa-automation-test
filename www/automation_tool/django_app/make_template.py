# Writes static/import_template/template.xlsx from template_spec.py
# run after every change of template_spec.py
import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
import template_spec as spec

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'import_template', 'template.xlsx')
PREFIX = {spec.REQ: '[Required] ', spec.COND: '[Conditional] ', spec.OPT: '[Optional] '}
LAST_ROW = 1000


def main():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for sheet in spec.SHEET_ORDER:
        ws = wb.create_sheet(sheet)
        for i, c in enumerate(spec.sheet_columns(sheet), start=1):
            letter = get_column_letter(i)
            head = ws.cell(row=1, column=i, value=c['name'])
            head.font = Font(bold=True)
            head.fill = PatternFill('solid', fgColor=spec.COLORS[c['level']])
            hint = ws.cell(row=2, column=i, value=PREFIX[c['level']] + c['hint'])
            hint.font = Font(italic=True, color='808080')
            hint.alignment = Alignment(wrap_text=True, vertical='top')
            ws.column_dimensions[letter].width = c['width']
            if c['choices']:
                dv = DataValidation(type='list', formula1=f'"{c["choices"]}"', allow_blank=True, showErrorMessage=True,
                                    errorTitle='Invalid value', error='Choose a value from the list.')
                dv.add(f'{letter}2:{letter}{LAST_ROW}')
                ws.add_data_validation(dv)
        ws.freeze_panes = 'A3'
    wb.save(OUT)
    print('written', OUT, len(spec.SHEET_ORDER), 'sheets')


if __name__ == '__main__':
    main()
