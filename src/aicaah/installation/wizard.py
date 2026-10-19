"""터미널 번호 선택 설치. 최종 확인 전에는 파일이나 서버를 만들지 않는다."""
from pathlib import Path
import sys
from parsing import settings
from output import localization
from storage import settings_store


class Wizard:
    """표시 언어·폴더·구조 기준 선택과 이전 이동을 보유한다."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.config = settings.defaults()
        self.config['sources'] = []
        self.locale = 'en'
        self.existing = False

    def text(self, key, **values):
        return localization.message(key, self.locale, **values)

    def menu(self, title, choices, back=True):
        """범위 밖 번호는 재입력하고 -1·EOF·Ctrl+C는 취소한다."""
        print('\n' + title)
        for number, label in enumerate(choices, 1): print(f'  {number}. {label}')
        if back: print('  0. ' + self.text('wizard.back'))
        print(' -1. ' + self.text('action.cancel'))
        while True:
            value = input('> ').strip()
            if value == '-1': raise EOFError()
            if value.isdecimal() and (1 <= int(value) <= len(choices) or back and value == '0'):
                return int(value)
            print(self.text('wizard.number'))

    def folder(self, bounded=False):
        """기존 디렉터리를 번호로 탐색하며 검사 범위는 프로젝트 안으로 제한한다."""
        current = self.root
        while True:
            try:
                children = sorted((p for p in current.iterdir() if p.is_dir() and not p.name.startswith('.')), key=lambda p:p.name.casefold())
            except OSError:
                children = []
            choice = self.menu(str(current), [self.text('wizard.useFolder'), self.text('wizard.parent'),
                self.text('wizard.enterPath')] + [p.name + '/' for p in children])
            if choice == 0: return None
            try:
                if choice == 1:
                    if not current.is_dir(): raise ValueError()
                    if bounded: settings.inside(self.root, current.resolve().relative_to(self.root).as_posix())
                    return current.resolve()
                if choice == 2: target = current.parent
                elif choice == 3:
                    entered = input(self.text('wizard.pathPrompt') + '\n> ').strip()
                    if entered == '-1': raise EOFError()
                    if not entered: continue
                    target = Path(entered).expanduser()
                    if not target.is_absolute(): target = current / target
                else: target = children[choice - 4]
                target = target.resolve()
                if not target.is_dir(): raise ValueError()
                if bounded: settings.inside(self.root, target.relative_to(self.root).as_posix())
                current = target
            except (OSError, ValueError):
                print(self.text('wizard.invalidFolder'))

    def language(self):
        choice = self.menu('1/7 · English / 한국어 / 中文 / 日本語', ['English', '한국어', '中文', '日本語'], back=False)
        self.locale = settings.LOCALES[choice - 1]
        self.config['locale'] = self.locale
        return True

    def project(self):
        print('\n2/7 · ' + self.text('wizard.project'))
        selected = self.folder()
        if selected is None: return False
        if selected != self.root:
            self.config['sources'] = []
            self.config['structure']['modules'] = []
            self.config['standards']['rules'] = []
        self.root = selected
        prior = settings.load(selected)
        self.existing = prior is not None
        if self.existing:
            print(self.text('setup.existing'))
            print(str(settings.configuration_path(selected)))
        return True

    def languages(self):
        labels = ['Python', 'C#', 'JavaScript', 'TypeScript', 'Java', 'Go']
        while True:
            chosen = self.config['languages']
            choice = self.menu('3/7 · ' + self.text('settings.languages'), [self.text('wizard.next')] +
                [('✓ ' if key in chosen else '· ') + label for key, label in zip(settings.LANGUAGES, labels)])
            if choice == 0: return False
            if choice == 1:
                if chosen: return True
                print(self.text('wizard.required')); continue
            key = settings.LANGUAGES[choice - 2]
            if key in chosen: chosen.remove(key)
            else: chosen.append(key)

    def folders(self, modules=False):
        title = ('5/7 · ' + self.text('settings.modules')) if modules else ('4/7 · ' + self.text('wizard.sources'))
        while True:
            paths = [m['path'] for m in self.config['structure']['modules']] if modules else self.config['sources']
            print('\n' + self.text('wizard.selected') + ': ' + (', '.join(paths) or self.text('wizard.none')))
            if modules: print(self.text('wizard.moduleHelp'))
            choice = self.menu(title, [self.text('wizard.next'), self.text('wizard.addFolder')] +
                [self.text('action.remove') + ': ' + p for p in paths])
            if choice == 0: return False
            if choice == 1:
                if not modules and not paths: print(self.text('wizard.required')); continue
                if modules and any(not self.source_contains(p) for p in paths):
                    print(self.text('wizard.moduleInside')); continue
                return True
            if choice == 2:
                folder = self.folder(bounded=True)
                if folder is None: continue
                relative = folder.relative_to(self.root).as_posix()
                if modules and not self.source_contains(relative):
                    print(self.text('wizard.moduleInside')); continue
                if relative not in paths: paths.append(relative)
            else: paths.pop(choice - 3)
            if modules:
                self.config['structure']['modules'] = [{'id':'module'+str(i+1), 'path':p} for i,p in enumerate(paths)]

    def source_contains(self, path):
        return any(s == '.' or path == s or path.startswith(s + '/') for s in self.config['sources'])

    def rule_label(self, rule):
        return '{} / {} ≤ {} · {} · {}'.format(self.text('unit.' + rule['unit']),
            self.text('metric.' + rule['metric']), rule['max'],
            self.text('wizard.allSources') if rule['scope'] == '**' else rule['scope'], self.text('depth.' + rule['depth']))

    def add_rule(self):
        """단위·지표·폴더·깊이를 선택한 뒤 0 이상의 숫자만 입력한다."""
        units = list(settings.METRICS)
        choice = self.menu(self.text('settings.unit'), [self.text('unit.' + key) for key in units])
        if not choice: return
        unit = units[choice - 1]
        metrics = settings.METRICS[unit]
        choice = self.menu(self.text('settings.metric'), [self.text('metric.' + key) for key in metrics])
        if not choice: return
        metric = metrics[choice - 1]
        choice = self.menu(self.text('settings.scope'), [self.text('wizard.allSources'), self.text('wizard.chooseScope')])
        if not choice: return
        scope = '**'
        if choice == 2:
            folder = self.folder(bounded=True)
            if folder is None: return
            relative = folder.relative_to(self.root).as_posix()
            scope = relative + '/**' if relative != '.' else '**'
        choice = self.menu(self.text('settings.depth'), [self.text('depth.direct'), self.text('depth.recursive')])
        if not choice: return
        depth = ('direct', 'recursive')[choice - 1]
        while True:
            value = input(self.text('wizard.maximum') + '\n> ').strip()
            if value == '-1': raise EOFError()
            if not value: return
            if value.isdecimal(): break
            print(self.text('wizard.nonnegative'))
        rules = self.config['standards']['rules']
        key = 1
        while any(r['id'] == 'limit'+str(key) for r in rules): key += 1
        rules.append({'id':'limit'+str(key), 'unit':unit, 'metric':metric, 'max':int(value),
                      'scope':scope, 'depth':depth, 'enabled':True})

    def limits(self):
        while True:
            rules = self.config['standards']['rules']
            print('\n' + self.text('wizard.limitsHelp'))
            for rule in rules: print('  ' + self.rule_label(rule))
            choice = self.menu('6/7 · ' + self.text('settings.rules'), [self.text('wizard.next'), self.text('wizard.addLimit')] +
                [self.text('action.remove') + ': ' + self.rule_label(rule) for rule in rules])
            if choice == 0: return False
            if choice == 1: return True
            if choice == 2: self.add_rule()
            else: rules.pop(choice - 3)

    def preview(self):
        print('\n7/7 · ' + self.text('setup.preview'))
        print(self.text('wizard.project') + ': ' + str(self.root))
        print(self.text('app.language') + ': ' + ('English', '한국어', '中文', '日本語')[settings.LOCALES.index(self.locale)])
        print(self.text('settings.languages') + ': ' + ', '.join(self.config['languages']))
        print(self.text('wizard.sources') + ': ' + ', '.join(self.config['sources']))
        print(self.text('settings.modules') + ': ' + (', '.join(m['path'] for m in self.config['structure']['modules']) or self.text('wizard.none')))
        for rule in self.config['standards']['rules']: print('  ' + self.rule_label(rule))
        if not self.config['standards']['rules']: print(self.text('wizard.noLimits'))
        print(self.text('wizard.preserve'))
        print(self.text('wizard.target') + ': ' + str(self.root / settings.FILE))


def run(args):
    """명시적 최종 확인 후 공용 설정 저장과 다시 읽기 검증을 실행한다."""
    wizard = Wizard(args.root)
    print('AICAAH — AI Coding Agent Architecture Harness · 0.1 beta')
    steps = [wizard.language, wizard.project, wizard.languages, wizard.folders,
             lambda: wizard.folders(modules=True), wizard.limits]
    step = 0
    try:
        while True:
            if step < len(steps):
                forward = steps[step]()
                if wizard.existing: return 0
                step += 1 if forward else -1
                continue
            settings.validate(wizard.config)
            wizard.preview()
            if getattr(args, 'dry_run', False): return 0
            if wizard.menu(wizard.text('wizard.confirm'), [wizard.text('wizard.save')]) == 0:
                step -= 1; continue
            settings_store.save(wizard.root, wizard.config, None)
            if settings.load(wizard.root) != wizard.config: raise ValueError('Configuration verification failed')
            print('\n' + wizard.text('wizard.complete'))
            print(wizard.text('wizard.nextSteps'))
            return 0
    except (EOFError, KeyboardInterrupt):
        print('\n' + wizard.text('setup.cancelled')); return 0
    except (ValueError, OSError) as error:
        print(wizard.text('wizard.failed') + ': ' + str(error), file=sys.stderr); return 2
