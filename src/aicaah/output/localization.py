"""표시 전용 네 언어 카탈로그. 코드·사용자 원문·판정 식별자를 번역하지 않는다."""
import json
import re
import string
from pathlib import Path
from functools import lru_cache
from parsing import settings

CATALOG = {
    "setup.title": ("AICAAH setup", "AICAAH 설치", "AICAAH 安装", "AICAAH セットアップ"),
    "setup.languages": ("Programming languages (comma separated)", "프로그래밍 언어 (쉼표 구분)", "编程语言（逗号分隔）", "プログラミング言語（カンマ区切り）"),
    "setup.sources": ("Source folders (comma separated)", "소스 폴더 (쉼표 구분)", "源代码文件夹（逗号分隔）", "ソースフォルダー（カンマ区切り）"),
    "setup.modules": ("Module folders (comma separated)", "모듈 경계 폴더 (쉼표 구분)", "模块文件夹（逗号分隔）", "モジュールのフォルダー（カンマ区切り）"),
    "setup.limits": ("Limits, e.g. folder.files=10,class.functions=20 (empty: observe only)", "한도, 예: folder.files=10,class.functions=20 (빈 값: 관측만)", "上限，例如 folder.files=10,class.functions=20（留空：仅观测）", "上限の例 folder.files=10,class.functions=20（空欄：観測のみ）"),
    "setup.confirm": ("Save this configuration? [y/N]", "이 설정을 저장할까요? [y/N]", "保存此配置？[y/N]", "この設定を保存しますか？[y/N]"),
    "setup.cancelled": ("Setup cancelled. No files changed.", "설치를 취소했습니다. 파일 변경 없음.", "安装已取消，未更改任何文件。", "セットアップを中止しました。ファイルの変更はありません。"),
    "setup.saved": ("Configuration saved. Set module boundaries and limits with: aicaah settings", "설정 저장 완료. 모듈 경계·한도 설정: aicaah settings", "配置已保存。设置模块边界和数量限制：aicaah settings", "設定を保存しました。モジュール境界と上限の設定：aicaah settings"),
    "setup.existing": ("Existing configuration preserved.", "기존 설정을 보존했습니다.", "已保留现有配置。", "既存の設定を保持しました。"),
    "setup.runtime": ("Runtime", "실행 환경", "运行环境", "実行環境"),
    "setup.preview": ("Installation preview", "설치 미리보기", "安装预览", "セットアップの確認"),
    "setup.observe": ("No universal limits are imposed. Configure explicit limits in settings.", "보편 한도를 강제하지 않습니다. 설정에서 원하는 한도를 지정하세요.", "不强制统一数量限制，请在设置中指定。", "一律の上限は強制しません。設定で上限を指定してください。"),
    "app.title": ("Code map", "코드 통합 지도", "代码地图", "コードマップ"),
    "app.settings": ("Structure settings", "구조 설정", "结构设置", "構造設定"),
    "app.language": ("Display language", "표시 언어", "显示语言", "表示言語"),
    "app.overview": ("Overview", "전체 오버뷰", "总览", "概要"),
    "app.findings": ("Findings", "지적", "问题", "指摘"),
    "app.implementation": ("Implementation", "구현", "实现", "実装"),
    "app.review": ("Document review", "문서 변경 검토", "文档变更审核", "文書変更の確認"),
    "app.phases": ("Phases", "페이즈", "阶段", "フェーズ"),
    "app.problems": ("Problems only", "문제만", "仅问题", "問題のみ"),
    "app.edges": ("All references", "모든 참조선", "所有引用", "すべての参照"),
    "app.fit": ("Fit", "맞춤", "适应", "全体表示"),
    "app.mode": ("Workflow", "작업 모드", "工作模式", "作業モード"),
    "app.code": ("Code edits", "코드 수정", "代码修改", "コード編集"),
    "app.docToCode": ("Document → code", "문서 → 코드", "文档 → 代码", "文書 → コード"),
    "app.codeToDoc": ("Code → document", "코드 → 문서", "代码 → 文档", "コード → 文書"),
    "app.deny": ("Documents only", "문서만 수정", "仅修改文档", "文書のみ編集"),
    "app.allow": ("Allow code edits", "코드 수정 허용", "允许修改代码", "コード編集を許可"),
    "app.request": ("Request approval", "필요 시 수락 요청", "请求批准", "承認を依頼"),
    "app.checking": ("Checking current state…", "표시 판정의 최신 여부 확인 중…", "正在检查最新状态…", "最新の判定を確認中…"),
    "app.loadingMode": ("Reading current mode…", "현재 모드 확인 중…", "正在读取当前模式…", "現在のモードを確認中…"),
    "app.reviewTitle": ("Review document changes", "문서 변경 체크", "审核文档变更", "文書変更の確認"),
    "app.progress": ("Review progress", "체크 진행률", "审核进度", "確認の進捗"),
    "action.cancel": ("Cancel", "취소", "取消", "キャンセル"),
    "action.run": ("Run", "실행", "执行", "実行"),
    "action.close": ("Close", "닫기", "关闭", "閉じる"),
    "action.save": ("Save and recheck", "저장 후 재검사", "保存并重新检查", "保存して再検査"),
    "action.add": ("Add", "추가", "添加", "追加"),
    "action.remove": ("Remove", "제거", "移除", "削除"),
    "settings.description": ("Choose module boundaries and limits for this project. Existing document contracts remain active.", "프로젝트의 모듈 경계와 한도를 설정합니다. 기존 문서 계약도 계속 적용됩니다.", "设置项目的模块边界和数量限制。现有文档约束仍然有效。", "プロジェクトのモジュール境界と上限を設定します。既存の文書契約も引き続き適用されます。"),
    "settings.modules": ("Module boundaries", "모듈 경계", "模块边界", "モジュール境界"),
    "settings.sources": ("Source folders (one per line)", "소스 폴더 (한 줄에 하나)", "源代码文件夹（每行一个）", "ソースフォルダー（1行に1つ）"),
    "settings.languages": ("Programming languages", "프로그래밍 언어", "编程语言", "プログラミング言語"),
    "settings.exclude": ("Excluded paths (one glob per line)", "제외 경로 (한 줄에 glob 하나)", "排除路径（每行一个 glob）", "除外パス（1行に1つの glob）"),
    "app.changeMode": ("Change workflow", "작업 모드 전환", "切换工作模式", "作業モードの切り替え"),
    "app.editPolicy": ("Code edit policy", "코드 수정 정책", "代码修改策略", "コード編集ポリシー"),
    "settings.rules": ("Structure limits", "구조 한도", "结构数量限制", "構造の上限"),
    "settings.id": ("ID", "ID", "ID", "ID"),
    "settings.path": ("Folder path", "폴더 경로", "文件夹路径", "フォルダーパス"),
    "settings.unit": ("Unit", "단위", "单位", "単位"),
    "settings.metric": ("Count", "셈", "计数项", "集計対象"),
    "settings.maximum": ("Maximum", "최대 허용량", "最大允许数量", "許容上限"),
    "settings.scope": ("Path scope", "적용 경로", "适用路径", "適用パス"),
    "settings.depth": ("Counting depth", "집계 깊이", "统计深度", "集計範囲"),
    "settings.enabled": ("Enabled", "활성", "启用", "有効"),
    "settings.overrides": ("Overrides and exceptions (JSON)", "범위 재정의·예외 (JSON)", "范围覆盖和例外（JSON）", "範囲の上書き・例外（JSON）"),
    "settings.saved": ("Saved. Recheck requested.", "저장했습니다. 재검사를 요청했습니다.", "已保存，已请求重新检查。", "保存しました。再検査を要求しました。"),
    "settings.conflict": ("Settings changed elsewhere. Reload before saving.", "다른 곳에서 설정이 변경됐습니다. 다시 불러온 뒤 저장하세요.", "配置已被其他操作修改，请重新加载后保存。", "別の操作で設定が変更されました。再読み込みして保存してください。"),
    "unit.folder": ("Folder", "폴더", "文件夹", "フォルダー"),
    "unit.module": ("Module", "모듈", "模块", "モジュール"),
    "unit.file": ("File", "파일", "文件", "ファイル"),
    "unit.class": ("Class", "클래스", "类", "クラス"),
    "unit.interface": ("Interface", "인터페이스", "接口", "インターフェース"),
    "unit.function": ("Function", "함수", "函数", "関数"),
    "metric.files": ("Files", "파일 수", "文件数", "ファイル数"),
    "metric.folders": ("Subfolders", "하위 폴더 수", "子文件夹数", "サブフォルダー数"),
    "metric.modules": ("Modules", "모듈 수", "模块数", "モジュール数"),
    "metric.classes": ("Classes", "클래스 수", "类数", "クラス数"),
    "metric.interfaces": ("Interfaces", "인터페이스 수", "接口数", "インターフェース数"),
    "metric.functions": ("Functions / methods", "함수·메서드 수", "函数／方法数", "関数・メソッド数"),
    "metric.variables": ("Variables / fields", "변수·필드 수", "变量／字段数", "変数・フィールド数"),
    "metric.parameters": ("Parameters", "매개변수 수", "参数数", "パラメーター数"),
    "metric.locals": ("Local variables", "지역 변수 수", "局部变量数", "ローカル変数数"),
    "depth.direct": ("Direct ownership", "직접 소유", "直接所属", "直接の所有"),
    "depth.recursive": ("All descendants", "하위 전체", "全部下级", "すべての下位要素"),
    "finding.limit": ("{target}: {metric} {actual} exceeds {maximum} ({depth}; {rule})", "{target}: {metric} {actual}개가 한도 {maximum}개 초과 ({depth}; {rule})", "{target}：{metric} {actual} 超过上限 {maximum}（{depth}；{rule}）", "{target}：{metric} {actual} が上限 {maximum} を超過（{depth}；{rule}）"),
    "finding.unavailable": ("{target}: {metric} could not be measured ({rule})", "{target}: {metric} 측정 근거 없음 ({rule})", "{target}：无法测量{metric}（{rule}）", "{target}：{metric} を測定できません（{rule}）"),
    'wizard.back': ('Previous', '이전', '上一步', '戻る'),
    'wizard.next': ('Next', '다음', '下一步', '次へ'),
    'wizard.number': ('Enter one of the displayed numbers.', '화면에 표시된 번호를 입력하세요.', '请输入显示的编号。', '表示された番号を入力してください。'),
    'wizard.project': ('Project folder', '프로젝트 폴더', '项目文件夹', 'プロジェクトフォルダー'),
    'wizard.useFolder': ('Select this folder', '이 폴더 선택', '选择此文件夹', 'このフォルダーを選択'),
    'wizard.parent': ('Open parent folder', '상위 폴더로 이동', '打开上级文件夹', '親フォルダーを開く'),
    'wizard.enterPath': ('Enter another folder path', '다른 폴더 경로 직접 입력', '输入其他文件夹路径', '別のフォルダーパスを入力'),
    'wizard.pathPrompt': ('Folder path (blank: return; -1: cancel)', '폴더 경로 (빈 입력: 돌아가기, -1: 취소)', '文件夹路径（留空返回，-1 取消）', 'フォルダーパス（空欄で戻る、-1 で中止）'),
    'wizard.invalidFolder': ('Select an accessible folder inside the allowed location.', '허용 범위 안의 접근 가능한 폴더를 선택하세요.', '请选择允许范围内可访问的文件夹。', '許可範囲内のアクセス可能なフォルダーを選択してください。'),
    'wizard.required': ('Select at least one item before continuing.', '하나 이상 선택한 뒤 다음으로 진행하세요.', '至少选择一项后继续。', '1つ以上選択してから進んでください。'),
    'wizard.sources': ('Folders to inspect', '검사할 폴더', '检查的文件夹', '検査するフォルダー'),
    'wizard.selected': ('Selected', '선택 항목', '已选择', '選択済み'),
    'wizard.none': ('None', '없음', '无', 'なし'),
    'wizard.addFolder': ('Add a folder', '폴더 추가', '添加文件夹', 'フォルダーを追加'),
    'wizard.moduleHelp': ('A selected folder is one module boundary. You may continue without modules.', '선택한 폴더를 하나의 모듈 경계로 봅니다. 모듈 지정 없이 진행할 수도 있습니다.', '所选文件夹定义一个模块边界，也可以不指定模块。', '選択したフォルダーを1つのモジュール境界とします。未指定でも進めます。'),
    'wizard.moduleInside': ('Module folders must be inside the folders selected for inspection.', '모듈은 검사할 폴더 안에서 선택하세요.', '模块必须位于选定的检查文件夹内。', 'モジュールは検査対象フォルダー内から選択してください。'),
    'wizard.allSources': ('All inspected paths', '전체 검사 경로', '全部检查路径', 'すべての検査対象パス'),
    'wizard.chooseScope': ('Choose a folder and its descendants', '폴더와 그 하위 경로 선택', '选择文件夹及其子路径', 'フォルダーとその配下を選択'),
    'wizard.maximum': ('Maximum allowed count (0 is valid; blank: return; -1: cancel)', '최대 허용 개수 (0도 유효, 빈 입력: 돌아가기, -1: 취소)', '最大允许数量（0 有效；留空返回；-1 取消）', '許容上限（0 も有効、空欄で戻る、-1 で中止）'),
    'wizard.nonnegative': ('Enter a whole number of 0 or greater.', '0 이상의 정수를 입력하세요.', '请输入大于或等于 0 的整数。', '0 以上の整数を入力してください。'),
    'wizard.limitsHelp': ('Choose what to count and its limit. No new limits are added unless you select them.', '단위와 셀 항목을 고르고 최대 개수를 정합니다. 선택하지 않은 한도는 추가하지 않습니다.', '选择计数单位、项目和上限。未选择的限制不会添加。', '単位・集計対象・上限を選択します。未指定の上限は追加しません。'),
    'wizard.addLimit': ('Add a count limit', '개수 제한 추가', '添加数量限制', '個数制限を追加'),
    'wizard.noLimits': ('No additional count limits selected.', '추가한 개수 제한 없음.', '未添加数量限制。', '追加の個数制限はありません。'),
    'wizard.preserve': ('Existing document contracts, approvals and workflow stay in effect.', '기존 문서 계약·승인·작업 모드는 유지됩니다.', '现有文档约束、审批和工作模式保持不变。', '既存の文書契約・承認・作業モードは維持されます。'),
    'wizard.target': ('Configuration file to create', '생성할 설정 파일', '将创建的配置文件', '作成する設定ファイル'),
    'wizard.confirm': ('Save these settings?', '이 설정을 저장할까요?', '保存这些设置？', 'この設定を保存しますか？'),
    'wizard.save': ('Confirm and install', '확인 후 설치', '确认并安装', '確認してインストール'),
    'wizard.complete': ('Setup complete. Saved configuration verified.', '설치 완료. 저장된 설정 검증 완료.', '安装完成，已验证保存的配置。', 'セットアップ完了。保存した設定を検証しました。'),
    'wizard.nextSteps': ('In the selected project folder, run aicaah ask status to start the code map. Choose the workflow in its settings.', '선택한 프로젝트 폴더에서 aicaah ask status를 실행해 코드맵을 시작하세요. 화면에서 작업 모드를 선택할 수 있습니다.', '在选定的项目文件夹中运行 aicaah ask status 启动代码地图，并在界面中选择工作模式。', '選択したプロジェクトフォルダーで aicaah ask status を実行するとコードマップが起動します。画面で作業モードを選択できます。'),
    'wizard.failed': ('Setup could not finish', '설치를 완료하지 못했습니다', '无法完成安装', 'セットアップを完了できませんでした'),
}


def message(key, locale="en", **values):
    """번역 키와 명시된 자리표시자를 해석한다."""
    if locale not in settings.LOCALES: raise ValueError("Unsupported display language")
    return CATALOG[key][settings.LOCALES.index(locale)].format(**values)


def catalog(locale):
    """선택 언어의 표시 자료만 브라우저에 전달한다."""
    return {key:values[settings.LOCALES.index(locale)] for key,values in CATALOG.items()}


@lru_cache(maxsize=4)
def map_catalog(locale):
    """동적 지도 문구만 번역하며 코드·문서 본문은 입력으로 받지 않는다."""
    entries = json.loads((Path(__file__).parent.parent / 'locales' / 'map.json').read_text(encoding='utf-8'))
    return {key:values[settings.LOCALES.index(locale)] for key,values in entries.items()}


def validate_catalogs():
    """모든 언어의 키·자리표시자 계약을 검사한다."""
    errors = []
    for key,values in CATALOG.items():
        placeholders = [{name for _,name,_,_ in string.Formatter().parse(value) if name is not None} for value in values]
        if len(values) != 4 or any(not value for value in values) or any(v != placeholders[0] for v in placeholders):
            errors.append(key)
    return errors


def shell(page, locale):
    """정적 화면 문구만 번역한다. JS의 상태값과 삽입된 사용자 자료는 보존한다."""
    head, separator, script = page.partition("<script>")
    head = head.replace('<html lang="ko">', '<html lang="'+locale+'">')
    for key,values in CATALOG.items():
        if not key.startswith(("app.", "action.")): continue
        translated = values[settings.LOCALES.index(locale)]
        head = re.sub(r'>(\s*)'+re.escape(values[1])+r'(\s*)(?=<)', lambda m:'>'+m[1]+translated+m[2], head)
        head = head.replace('"'+values[1]+'"', '"'+translated+'"')
    title = message('app.title', locale)
    head = head.replace('<title>'+title+'</title>', '<title>AICAAH · '+title+'</title>')
    head = head.replace('<h1>'+title+'</h1>', '<h1>AICAAH · '+title+'</h1>')
    return head + separator + script
