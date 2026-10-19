"""순서가 있는 프로젝트 설치. 기존 설정·문서·승인·훅 신뢰는 보존한다."""
import json
from pathlib import Path
import sys
from parsing import settings
from output import localization
from storage import settings_store


def initialize(args):
    """선택→미리보기→확인→저장. 취소와 재실행은 사용자 파일을 변경하지 않는다."""
    if not args.yes and not any((args.language, args.languages, args.source, args.module, args.limit, args.config)):
        from installation import wizard
        return wizard.run(args)
    locale = args.language or "en"
    try:
        prior = settings.load(args.root)
        if prior is not None:
            print(localization.message("setup.existing", prior["locale"]))
            print(json.dumps(prior, ensure_ascii=False, indent=2)); return 0
        if locale not in settings.LOCALES: raise ValueError("Unsupported display language")
        print(localization.message("setup.title", locale))
        print(localization.message("setup.runtime", locale) + ": Python " + sys.version.split()[0])
        config = settings.defaults()
        config["locale"] = locale
        chosen = args.languages or ",".join(settings.LANGUAGES)
        sources = args.source or ["src"]
        config["languages"] = [x.strip() for x in chosen.split(",")]
        config["sources"] = [settings.relative(x.strip()) for x in sources]
        modules = args.module or config['sources']
        config["structure"]["modules"] = [{"id":"module"+str(i+1), "path":settings.relative(path.strip())} for i,path in enumerate(modules)]
        limits = args.limit or []
        for value in limits:
            if not value.strip(): continue
            selector, maximum = value.strip().split('=', 1)
            unit, metric = selector.split('.', 1)
            config['standards']['rules'].append({'id':selector, 'unit':unit, 'metric':metric,
                'max':int(maximum), 'scope':'**', 'depth':'direct', 'enabled':True})
        if args.config:
            config = settings.validate(json.loads(Path(args.config).read_text(encoding="utf-8-sig")))
            locale = config["locale"]
        settings.validate(config)
        for folder in config["sources"]: settings.inside(args.root, folder)
        print(localization.message("setup.preview", locale))
        print(json.dumps(config, ensure_ascii=False, indent=2))
        print(localization.message("setup.observe", locale))
        if args.dry_run: return 0
        if not args.yes and input(localization.message("setup.confirm", locale) + " ").strip().lower() not in ("y", "yes"):
            print(localization.message("setup.cancelled", locale)); return 0
        settings_store.save(args.root, config, None)
        print(localization.message("setup.saved", locale)); return 0
    except (ValueError, OSError, EOFError) as error:
        print(str(error), file=sys.stderr); return 2


def configure(args):
    """설정 조회·파일 적용. 적용은 현재 지문을 비교한 뒤 재판정 입력으로 저장한다."""
    try:
        current = settings.load(args.root)
        if args.schema:
            print(json.dumps(settings.schema(), ensure_ascii=False)); return 0
        if args.file:
            expected = settings_store.fingerprint(args.root)
            value = settings.validate(json.loads(Path(args.file).read_text(encoding="utf-8-sig")))
            if not args.dry_run: settings_store.save(args.root, value, expected)
            current = value
        print(json.dumps(current or settings.defaults(), ensure_ascii=False, indent=2)); return 0
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr); return 2
