// 참조 그래프 추출기(SPEC-36 2.8.1). 작업 파일의 컴파일 단위마다 선언·참조를 Roslyn으로 뽑아 바이너리로 쓴다.
// 계층·판정은 모른다. 엔진(refs.py)이 작업 파일을 만들고 결과를 판정(layers.py)에 넘긴다.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

/// <summary>명령줄 진입과 작업 파일 처리.</summary>
public static class RefGraph
{
    /// <summary>작업 파일(args[0])을 읽어 단위마다 결과를 그 단위의 `out` 경로에 쓴다. 성공 0, 실패 1.</summary>
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length != 1) { Console.Error.WriteLine("사용: RefGraph <job.bin>"); return 1; }
            var job = BinaryValue.Read(args[0]);
            var trees = new Dictionary<string, SyntaxTree>();
            var strings = new Dictionary<string, HashSet<string>>();
            foreach (var rule in job.GetProperty("strings").EnumerateArray())
                foreach (var api in rule.GetProperty("apis").EnumerateArray())
                {
                    if (!strings.TryGetValue(api.GetString(), out var receivers)) strings[api.GetString()] = receivers = new HashSet<string>();
                    receivers.Add(rule.GetProperty("receiver").GetString());
                }
            var root = job.GetProperty("root").GetString();
            foreach (var unit in job.GetProperty("units").EnumerateArray())
            {
                var output = new Output();
                RunUnit(unit, root, trees, strings, output);
                output.Write(unit.GetProperty("out").GetString());
            }
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e.ToString());
            return 1;
        }
    }

    /// <summary>단위 하나: 정의 기호로 구문 트리를 만들고(같은 파일·정의는 한 번만 파싱) 컴파일한 뒤 걷는 파일을 걷는다.</summary>
    static void RunUnit(BinaryValue unit, string root, Dictionary<string, SyntaxTree> trees, Dictionary<string, HashSet<string>> strings, Output output)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var defines = unit.GetProperty("defines").EnumerateArray().Select(x => x.GetString()).ToArray();
        var options = new CSharpParseOptions(LanguageVersion.Latest, DocumentationMode.None, SourceCodeKind.Regular, defines);
        var defineKey = string.Join(";", defines);
        var walk = unit.GetProperty("walk").EnumerateArray().Select(x => x.GetString()).ToList();
        var context = unit.GetProperty("context").EnumerateArray().Select(x => x.GetString()).ToList();
        var unitTrees = new List<SyntaxTree>();
        var walkTrees = new List<SyntaxTree>();
        var walkSet = new HashSet<string>(walk);
        var sourceOverrides = unit.GetProperty("sourceOverrides").EnumerateArray()
            .ToDictionary(x => x.GetProperty("file").GetString(), x => x.GetProperty("source").GetString());
        foreach (var rel in walk.Concat(context).Distinct())
        {
            var source = sourceOverrides.TryGetValue(rel, out var replacement) ? replacement : Path.Combine(root, rel);
            var key = defineKey + "|" + rel + "|" + source + "|" + unit.GetProperty("variantKey").GetString();
            if (!trees.TryGetValue(key, out var tree))
            {
                var text = File.ReadAllText(source);
                tree = CSharpSyntaxTree.ParseText(text, options, rel, Encoding.UTF8);
                trees[key] = tree;
            }
            unitTrees.Add(tree);
            if (walkSet.Contains(rel)) walkTrees.Add(tree);
        }
        var refs = new List<MetadataReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dll in unit.GetProperty("refs").EnumerateArray().Select(x => x.GetString()))
            if (seen.Add(Path.GetFileName(dll)) && File.Exists(dll))
                refs.Add(MetadataReference.CreateFromFile(dll));
        var compilation = CSharpCompilation.Create("Unit", unitTrees, refs,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true, concurrentBuild: true));
        var results = new ConcurrentBag<FileResult>();
        Parallel.ForEach(walkTrees, tree => results.Add(new Walker(compilation.GetSemanticModel(tree), strings).Run()));
        foreach (var r in results.OrderBy(r => r.File, StringComparer.Ordinal))
            output.Merge(r);
        var errors = results.Sum(r => r.Errors);
        output.Units.Add(new Dictionary<string, object> {
            ["name"] = unit.GetProperty("name").GetString(), ["errors"] = errors, ["walked"] = walkTrees.Count,
            ["ms"] = (int)watch.ElapsedMilliseconds });
    }
}

/// <summary>선언 하나(열쇠는 문서 주석 id + @ + 첫 선언 파일).</summary>
sealed class Decl
{
    public string Key, Name, Kind, File, Access, Hash, Container, Type, SourceName, SourceParams;
    public int Line, End, Statements;
    public int Locals = -1;
    public List<(string name, string kind, int line, string scope)> Variables = new List<(string, string, int, string)>();
    public List<string> Mods = new List<string>(), Attrs = new List<string>(), Bases = new List<string>();
    public List<(string file, int line, int end)> Occurrences = new List<(string, int, int)>();
}

/// <summary>파일 하나를 걸은 결과(열쇠로 적는다. 번호는 합칠 때 붙인다).</summary>
sealed class FileResult
{
    public string File;
    public int Errors;
    /// <summary>해석 오류의 파일·줄·진단 코드·메시지를 보존한다.</summary>
    public readonly List<Dictionary<string, object>> Diagnostics = new List<Dictionary<string, object>>();
    public List<Decl> Decls = new List<Decl>();
    public List<(string from, string to, int line, bool write)> Edges = new List<(string, string, int, bool)>();
    public List<(string member, string target, bool external)> Overrides = new List<(string, string, bool)>();
    public List<(string from, int line, string api, string name, string type)> Strings = new List<(string, int, string, string, string)>();
    public List<(string from, int line, string name)> Unresolved = new List<(string, int, string)>();
}

/// <summary>한 파일의 선언·참조를 뽑는다.</summary>
sealed class Walker
{
    readonly SemanticModel model;
    readonly Dictionary<string, HashSet<string>> strings;
    readonly FileResult result = new FileResult();

    /// <summary>의미 모델과 문자열 API → 받는 형 목록.</summary>
    public Walker(SemanticModel model, Dictionary<string, HashSet<string>> strings)
    {
        this.model = model;
        this.strings = strings;
        result.File = model.SyntaxTree.FilePath;
    }

    /// <summary>모든 마디를 한 번 돈다.</summary>
    public FileResult Run()
    {
        foreach (var node in model.SyntaxTree.GetRoot().DescendantNodes())
        {
            switch (node)
            {
                case BaseTypeDeclarationSyntax _:
                case DelegateDeclarationSyntax _:
                case BaseMethodDeclarationSyntax _:
                case BasePropertyDeclarationSyntax _:
                case EnumMemberDeclarationSyntax _:
                    Declare(node, model.GetDeclaredSymbol(node));
                    break;
                case VariableDeclaratorSyntax v when v.Parent?.Parent is BaseFieldDeclarationSyntax:
                    Declare(v, model.GetDeclaredSymbol(v));
                    break;
            }
            switch (node)
            {
                case SimpleNameSyntax name when !InUsing(name):
                    var info = model.GetSymbolInfo(name);
                    foreach (var s in Resolve(info))
                        Edge(name, s, s is IFieldSymbol || s is IPropertySymbol ? IsWrite(name) : false);
                    if (info.Symbol == null && info.CandidateSymbols.IsEmpty && TypeLike(name) && From(name) is string from)
                        result.Unresolved.Add((from, name.GetLocation().GetLineSpan().StartLinePosition.Line + 1, name.Identifier.Text));
                    break;
                case ObjectCreationExpressionSyntax _:
                case ImplicitObjectCreationExpressionSyntax _:
                case ConstructorInitializerSyntax _:
                case ElementAccessExpressionSyntax _:
                case BinaryExpressionSyntax _:
                case PrefixUnaryExpressionSyntax _:
                case PostfixUnaryExpressionSyntax _:
                case AssignmentExpressionSyntax _:
                    foreach (var s in Resolve(model.GetSymbolInfo(node)))
                        if (s is IMethodSymbol || s is IPropertySymbol)
                            Edge(node, s, false);
                    break;
            }
            if (node is InvocationExpressionSyntax call)
            {
                StringCall(call);
                SerializedReads(call);
            }
            if (node is ConstructorDeclarationSyntax ctor && ctor.Initializer == null && !ctor.Modifiers.Any(SyntaxKind.StaticKeyword))
                BaseCtor(ctor, model.GetDeclaredSymbol(ctor)?.ContainingType);
            if (node is TypeDeclarationSyntax td && !td.Members.OfType<ConstructorDeclarationSyntax>().Any(c => !c.Modifiers.Any(SyntaxKind.StaticKeyword)))
                BaseCtor(td, model.GetDeclaredSymbol(td));
        }
        foreach (var diagnostic in model.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error))
        {
            result.Diagnostics.Add(new Dictionary<string, object> {
                ["file"] = result.File,
                ["line"] = diagnostic.Location.GetLineSpan().StartLinePosition.Line + 1,
                ["code"] = diagnostic.Id,
                ["message"] = diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture) });
        }
        result.Errors = result.Diagnostics.Count;
        return result;
    }

    /// <summary>형 이름 꼴: 대문자로 시작하고 멤버 접근·한정 이름의 오른쪽이 아니다.</summary>
    static bool TypeLike(SimpleNameSyntax name)
    {
        var text = name.Identifier.Text;
        if (text.Length == 0 || !char.IsUpper(text[0])) return false;
        if (name.Parent is MemberAccessExpressionSyntax ma && ma.Name == name) return false;
        if (name.Parent is QualifiedNameSyntax q && q.Right == name) return false;
        return !(name.Parent is MemberBindingExpressionSyntax);
    }

    /// <summary>using 지시문 안의 이름은 참조가 아니다.</summary>
    static bool InUsing(SyntaxNode node) => node.Ancestors().Any(a => a is UsingDirectiveSyntax);

    /// <summary>의미 선언과 모든 소스 선언 자리를 적는다. partial은 의미 열쇠 하나로 합친다.</summary>
    void Declare(SyntaxNode node, ISymbol symbol)
    {
        if (symbol == null || symbol.IsImplicitlyDeclared) return;
        var key = Key(symbol);
        if (key == null) return;
        var source = node is VariableDeclaratorSyntax ? node.Parent.Parent : node;
        var span = source.GetLocation().GetLineSpan();
        var occurrence = (result.File, span.StartLinePosition.Line + 1, span.EndLinePosition.Line + 1);
        var existing = result.Decls.FirstOrDefault(item => item.Key == key);
        if (existing != null) { existing.Occurrences.Add(occurrence); return; }
        var d = new Decl {
            Key = key, Name = symbol.Name, Kind = KindOf(symbol), File = result.File, Access = Access(symbol),
            Line = span.StartLinePosition.Line + 1, End = span.EndLinePosition.Line + 1,
            Container = symbol.ContainingType == null ? null : Key(symbol.ContainingType)
        };
        d.SourceName = node switch {
            MethodDeclarationSyntax method => method.Identifier.ValueText,
            PropertyDeclarationSyntax property => property.Identifier.ValueText,
            ConstructorDeclarationSyntax ctor => ctor.Identifier.ValueText,
            DestructorDeclarationSyntax destructor => "~" + destructor.Identifier.ValueText,
            OperatorDeclarationSyntax op => "operator" + op.OperatorToken.Text,
            ConversionOperatorDeclarationSyntax conversion => "operator" + conversion.Type.ToString().Replace(" ", ""),
            _ => symbol.Name
        };
        var parameters = node is BaseMethodDeclarationSyntax methodNode ? methodNode.ParameterList.Parameters :
            node is IndexerDeclarationSyntax indexer ? indexer.ParameterList.Parameters :
            node is DelegateDeclarationSyntax delegateNode ? delegateNode.ParameterList.Parameters : default;
        d.SourceParams = string.Join(",", parameters.Select(p =>
            string.Join(" ", p.Modifiers.Where(m => m.IsKind(SyntaxKind.RefKeyword) || m.IsKind(SyntaxKind.OutKeyword) || m.IsKind(SyntaxKind.InKeyword)).Select(m => m.Text)
                .Concat(new[] { p.Type?.ToString() ?? "" }))));
        d.Occurrences.Add(occurrence);
        if (symbol.IsStatic) d.Mods.Add("static");
        if (symbol.IsAbstract) d.Mods.Add("abstract");
        if (symbol.IsVirtual) d.Mods.Add("virtual");
        if (symbol.IsOverride) d.Mods.Add("override");
        if (symbol.IsSealed) d.Mods.Add("sealed");
        if (symbol is IFieldSymbol f)
        {
            if (f.IsConst) d.Mods.Add("const");
            if (f.IsReadOnly) d.Mods.Add("readonly");
            d.Type = f.Type.ToDisplayString();
        }
        foreach (var a in symbol.GetAttributes())
            if (a.AttributeClass != null) d.Attrs.Add(a.AttributeClass.ToDisplayString());
        if (symbol is INamedTypeSymbol t)
        {
            for (var b = t.BaseType; b != null; b = b.BaseType) d.Bases.Add(b.OriginalDefinition.ToDisplayString());
            foreach (var i in t.AllInterfaces) d.Bases.Add(i.OriginalDefinition.ToDisplayString());
            Implementations(t);
        }
        Overrides(symbol);
        if (node is BaseMethodDeclarationSyntax m && (m.Body != null || m.ExpressionBody != null))
        {
            SyntaxNode body = (SyntaxNode)m.Body ?? m.ExpressionBody;
            var tokens = string.Join(" ", body.DescendantTokens().Select(x => x.Text));
            using (var sha = SHA1.Create())
                d.Hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(tokens))).Replace("-", "").ToLowerInvariant();
            d.Statements = m.Body == null ? 1 : m.Body.DescendantNodes().OfType<StatementSyntax>().Count(s => !(s is BlockSyntax));
        }
        if (symbol is IMethodSymbol || (symbol is IPropertySymbol ip && ip.IsIndexer))
        {
            d.Locals = Locals(node);
            foreach (var child in node.DescendantNodes())
            {
                string name = null, kind = "지역 변수";
                if (child is ParameterSyntax parameter) { name = parameter.Identifier.Text; kind = "매개변수"; }
                else if (child is VariableDeclaratorSyntax variable && !(variable.Parent?.Parent is BaseFieldDeclarationSyntax)) name = variable.Identifier.Text;
                else if (child is ForEachStatementSyntax each) name = each.Identifier.Text;
                else if (child is SingleVariableDesignationSyntax designation) name = designation.Identifier.Text;
                else if (child is CatchDeclarationSyntax caught) name = caught.Identifier.Text;
                if (string.IsNullOrEmpty(name)) continue;
                var inner = child.Ancestors().TakeWhile(a => a != node).FirstOrDefault(a => a is LocalFunctionStatementSyntax || a is AnonymousFunctionExpressionSyntax);
                var scope = inner is LocalFunctionStatementSyntax local ? "지역 함수 " + local.Identifier.Text :
                    inner != null ? "람다 L" + (inner.GetLocation().GetLineSpan().StartLinePosition.Line + 1) : "";
                d.Variables.Add((name, kind, child.GetLocation().GetLineSpan().StartLinePosition.Line + 1, scope));
            }
        }
        result.Decls.Add(d);
    }

    /// <summary>메서드 본문 안 지역 변수 선언 수(지역 선언·foreach·catch·out var·패턴 변수, 지역 함수·람다 안 포함).</summary>
    static int Locals(SyntaxNode node)
    {
        var n = 0;
        foreach (var x in node.DescendantNodes())
        {
            switch (x)
            {
                case VariableDeclaratorSyntax v when v.Parent is VariableDeclarationSyntax decl
                                                     && !(decl.Parent is FieldDeclarationSyntax) && !(decl.Parent is EventFieldDeclarationSyntax):
                case ForEachStatementSyntax _:
                case SingleVariableDesignationSyntax _:
                    n++;
                    break;
                case CatchDeclarationSyntax c when c.Identifier.Text.Length > 0:
                    n++;
                    break;
            }
        }
        return n;
    }

    /// <summary>재정의·명시적 구현한 멤버(소스면 열쇠, 메타데이터면 외부).</summary>
    void Overrides(ISymbol symbol)
    {
        var targets = new List<ISymbol>();
        switch (symbol)
        {
            case IMethodSymbol m:
                if (m.OverriddenMethod != null) targets.Add(m.OverriddenMethod);
                targets.AddRange(m.ExplicitInterfaceImplementations);
                break;
            case IPropertySymbol p:
                if (p.OverriddenProperty != null) targets.Add(p.OverriddenProperty);
                targets.AddRange(p.ExplicitInterfaceImplementations);
                break;
            case IEventSymbol e:
                if (e.OverriddenEvent != null) targets.Add(e.OverriddenEvent);
                targets.AddRange(e.ExplicitInterfaceImplementations);
                break;
        }
        foreach (var t in targets) Override(symbol, t);
    }

    /// <summary>형의 암시적 인터페이스 구현(구현 멤버가 조상에 있어도 적는다).</summary>
    void Implementations(INamedTypeSymbol type)
    {
        foreach (var iface in type.AllInterfaces)
            foreach (var member in iface.GetMembers())
            {
                var impl = type.FindImplementationForInterfaceMember(member);
                if (impl != null) Override(impl, member);
            }
    }

    /// <summary>구현 멤버 → 대상 멤버 한 쌍. 구현 멤버가 소스가 아니면 버린다.</summary>
    void Override(ISymbol impl, ISymbol target)
    {
        var implKey = Key(Norm(impl));
        if (implKey == null) return;
        var t = Norm(target) ?? target.OriginalDefinition;
        var targetKey = Key(t);
        result.Overrides.Add((implKey, targetKey, targetKey == null));
    }

    /// <summary>둘러싼 선언에서 대상 심볼로 가는 참조 하나.</summary>
    void Edge(SyntaxNode node, ISymbol target, bool write)
    {
        var to = Key(target);
        if (to == null) return;
        var from = From(node);
        if (from == null) return;
        result.Edges.Add((from, to, node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, write));
    }

    /// <summary>초기화 절이 없는 생성자(또는 생성자를 선언하지 않은 형)가 부르는 기반형의 매개변수 없는 생성자.</summary>
    void BaseCtor(SyntaxNode node, INamedTypeSymbol type)
    {
        var baseType = type?.BaseType;
        if (baseType == null || type.TypeKind != TypeKind.Class) return;
        var ctor = baseType.InstanceConstructors.FirstOrDefault(c => c.Parameters.All(p => p.IsOptional));
        if (ctor != null && Key(Norm(ctor)) is string to)
        {
            var from = node is TypeDeclarationSyntax ? Key(type) : Key(model.GetDeclaredSymbol(node));
            if (from != null) result.Edges.Add((from, to, node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, false));
        }
    }

    /// <summary>실제 외부 JsonConvert 기본 호출이 읽는 봉인된 일반 DTO의 공개 필드. 사용자 설정·형 계약·알 수 없는 동적 형은 추측하지 않는다.</summary>
    void SerializedReads(InvocationExpressionSyntax call)
    {
        if (call.ArgumentList.Arguments.Count != 1) return;
        var name = call.Expression is MemberAccessExpressionSyntax access ? access.Name.Identifier.ValueText :
            (call.Expression as SimpleNameSyntax)?.Identifier.ValueText;
        if (name != "SerializeObject") return;
        var method = model.GetSymbolInfo(call).Symbol as IMethodSymbol;
        if (method?.Name != "SerializeObject" || method.ContainingType.ToDisplayString() != "Newtonsoft.Json.JsonConvert"
            || method.Locations.Any(l => l.IsInSource)) return;
        var type = model.GetTypeInfo(call.ArgumentList.Arguments[0].Expression).Type as INamedTypeSymbol;
        if (type == null || !type.IsSealed || !type.Locations.Any(l => l.IsInSource) || type.GetAttributes().Length != 0) return;
        // Inherited serializer contracts and properties can carry custom behavior; this path handles plain field DTOs only.
        if (type.BaseType?.SpecialType != SpecialType.System_Object || type.GetMembers().OfType<IPropertySymbol>().Any()) return;
        foreach (var field in type.GetMembers().OfType<IFieldSymbol>())
        {
            if (field.IsStatic || field.IsImplicitlyDeclared || field.DeclaredAccessibility != Accessibility.Public) continue;
            if (field.GetAttributes().Any(a => a.AttributeClass?.ToDisplayString() == "Newtonsoft.Json.JsonIgnoreAttribute"
                || a.AttributeClass?.ToDisplayString() == "System.NonSerializedAttribute")) continue;
            Edge(call, field, false);
        }
    }

    /// <summary>문자열 API를 문자열 글자로 부르고 받는 식의 형이 표의 받는 형(또는 그 자손)이면 (출발, 이름, 대상 형)을 남긴다.</summary>
    void StringCall(InvocationExpressionSyntax call)
    {
        string api = call.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            SimpleNameSyntax sn => sn.Identifier.Text,
            _ => null
        };
        if (api == null || !strings.TryGetValue(api, out var receivers)) return;
        var literal = call.ArgumentList.Arguments.Select(a => a.Expression).OfType<LiteralExpressionSyntax>()
            .FirstOrDefault(l => l.IsKind(SyntaxKind.StringLiteralExpression));
        if (literal == null) return;
        var from = From(call);
        if (from == null) return;
        var access = call.Expression as MemberAccessExpressionSyntax;
        var e = access?.Expression;
        ITypeSymbol receiverType = e == null || e is ThisExpressionSyntax ? Enclosing(call) : model.GetTypeInfo(e).Type;
        if (!Matches(receiverType, receivers)) return;
        ITypeSymbol target = null;
        if (e == null || e is ThisExpressionSyntax) target = Enclosing(call);
        else if (e is TypeOfExpressionSyntax tof) target = model.GetTypeInfo(tof.Type).Type;
        else if (e is InvocationExpressionSyntax inner && inner.Expression is MemberAccessExpressionSyntax gt && gt.Name.Identifier.Text == "GetType")
            target = model.GetTypeInfo(gt.Expression).Type;
        else if (e is InvocationExpressionSyntax inner2 && inner2.Expression is IdentifierNameSyntax gt2 && gt2.Identifier.Text == "GetType")
            target = Enclosing(call);
        else if (receiverType != null && receiverType.Locations.Any(l => l.IsInSource)) target = receiverType;
        result.Strings.Add((from, call.GetLocation().GetLineSpan().StartLinePosition.Line + 1, api,
            literal.Token.ValueText, target == null ? null : Key(Norm(target))));
    }

    /// <summary>형 또는 그 조상·인터페이스의 전체 이름이 받는 형 목록에 있는가.</summary>
    static bool Matches(ITypeSymbol type, HashSet<string> receivers)
    {
        if (type == null) return false;
        if (type.AllInterfaces.Any(i => receivers.Contains(i.OriginalDefinition.ToDisplayString()))) return true;
        for (var t = type; t != null; t = t.BaseType)
            if (receivers.Contains(t.OriginalDefinition.ToDisplayString())) return true;
        return false;
    }

    /// <summary>둘러싼 형.</summary>
    INamedTypeSymbol Enclosing(SyntaxNode node)
    {
        var decl = node.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        return decl == null ? null : model.GetDeclaredSymbol(decl) as INamedTypeSymbol;
    }

    /// <summary>참조의 출발 선언: 둘러싼 멤버. 필드·자동 속성 초기화(상수 제외)·형 특성·기반 목록은 형.</summary>
    string From(SyntaxNode node)
    {
        foreach (var a in node.Ancestors())
        {
            switch (a)
            {
                case AccessorDeclarationSyntax _:
                    continue;
                case EqualsValueClauseSyntax eq when eq.Parent is PropertyDeclarationSyntax:
                    return TypeKey(a);
                case VariableDeclaratorSyntax v when v.Parent?.Parent is BaseFieldDeclarationSyntax fd:
                    if (fd is FieldDeclarationSyntax f && f.Modifiers.Any(SyntaxKind.ConstKeyword))
                        return Key(model.GetDeclaredSymbol(v));
                    return TypeKey(a);
                case BaseMethodDeclarationSyntax _:
                case BasePropertyDeclarationSyntax _:
                case EnumMemberDeclarationSyntax _:
                case DelegateDeclarationSyntax _:
                case BaseTypeDeclarationSyntax _:
                    return Key(model.GetDeclaredSymbol(a));
            }
        }
        return null;
    }

    /// <summary>둘러싼 형의 열쇠.</summary>
    string TypeKey(SyntaxNode node)
    {
        var t = node.AncestorsAndSelf().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        return t == null ? null : Key(model.GetDeclaredSymbol(t));
    }

    /// <summary>쓰기: 단순 대입의 왼쪽, out 인수(개체 초기화의 이름도 대입의 왼쪽이다).</summary>
    static bool IsWrite(SimpleNameSyntax name)
    {
        ExpressionSyntax e = name;
        if (name.Parent is MemberAccessExpressionSyntax ma && ma.Name == name) e = ma;
        if (e.Parent is AssignmentExpressionSyntax assign && assign.Left == e && assign.IsKind(SyntaxKind.SimpleAssignmentExpression))
            return true;
        return e.Parent is ArgumentSyntax arg && arg.RefKindKeyword.IsKind(SyntaxKind.OutKeyword);
    }

    /// <summary>해석 결과(확정 심볼, 없으면 후보 전부)를 모아 정규화한다. 생성자는 그 형도 함께(특성 이름은 생성자로만 해석된다).</summary>
    static IEnumerable<ISymbol> Resolve(SymbolInfo info)
    {
        var list = info.Symbol != null ? new[] { info.Symbol } : info.CandidateSymbols.ToArray();
        foreach (var s in list)
        {
            var n = Norm(s);
            if (n == null) continue;
            yield return n;
            if (n is IMethodSymbol m && m.MethodKind == MethodKind.Constructor) yield return m.ContainingType;
        }
    }

    /// <summary>확장 메서드는 원래 정의로, 접근자는 속성·이벤트로, 구성형은 원래 정의로. 지역·매개변수·이름공간은 버린다.</summary>
    public static ISymbol Norm(ISymbol s)
    {
        switch (s)
        {
            case IAliasSymbol alias:
                return Norm(alias.Target);
            case IMethodSymbol m:
                if (m.ReducedFrom != null) m = m.ReducedFrom;
                switch (m.MethodKind)
                {
                    case MethodKind.PropertyGet:
                    case MethodKind.PropertySet:
                    case MethodKind.EventAdd:
                    case MethodKind.EventRemove:
                        return m.AssociatedSymbol == null ? null : Norm(m.AssociatedSymbol);
                    case MethodKind.LocalFunction:
                    case MethodKind.AnonymousFunction:
                        return null;
                }
                m = m.OriginalDefinition;
                if (m.PartialImplementationPart != null) m = m.PartialImplementationPart;
                return m;
            case IPropertySymbol p:
                return p.OriginalDefinition;
            case IFieldSymbol f:
                if (f.AssociatedSymbol is IPropertySymbol) return null;
                return f.OriginalDefinition;
            case IEventSymbol e:
                return e.OriginalDefinition;
            case INamedTypeSymbol t:
                return t.IsTupleType || t.IsAnonymousType ? null : t.OriginalDefinition;
            default:
                return null;
        }
    }

    /// <summary>소스에 선언된 심볼의 열쇠(문서 주석 id + @ + 첫 선언 파일). 소스가 아니면 null.</summary>
    public static string Key(ISymbol s)
    {
        if (s == null) return null;
        var files = s.Locations.Where(l => l.IsInSource).Select(l => l.SourceTree.FilePath).ToList();
        if (files.Count == 0) return null;
        files.Sort(StringComparer.Ordinal);
        var id = DocumentationCommentId.CreateDeclarationId(s) ?? s.ToDisplayString();
        return id + "@" + files[0];
    }

    /// <summary>선언 종류 이름(엔진 members 표의 종류와 같은 낱말).</summary>
    static string KindOf(ISymbol s)
    {
        switch (s)
        {
            case INamedTypeSymbol t:
                if (t.TypeKind == TypeKind.Delegate) return "delegate";
                if (t.TypeKind == TypeKind.Interface) return "interface";
                if (t.TypeKind == TypeKind.Enum) return "enum";
                if (t.IsRecord) return "record";
                return t.TypeKind == TypeKind.Struct ? "struct" : "class";
            case IMethodSymbol m:
                if (m.MethodKind == MethodKind.Constructor || m.MethodKind == MethodKind.StaticConstructor) return "ctor";
                if (m.MethodKind == MethodKind.Destructor) return "dtor";
                if (m.MethodKind == MethodKind.UserDefinedOperator || m.MethodKind == MethodKind.Conversion) return "operator";
                return "method";
            case IPropertySymbol p:
                return p.IsIndexer ? "indexer" : "property";
            case IEventSymbol _:
                return "event";
            case IFieldSymbol f:
                if (f.ContainingType?.TypeKind == TypeKind.Enum) return "enum-member";
                return f.IsConst ? "const" : "field";
        }
        return "other";
    }

    /// <summary>접근 수준 낱말.</summary>
    static string Access(ISymbol s) => s.DeclaredAccessibility switch
    {
        Accessibility.Public => "public",
        Accessibility.Internal => "internal",
        Accessibility.Protected => "protected",
        Accessibility.ProtectedOrInternal => "protected",
        Accessibility.ProtectedAndInternal => "private",
        _ => "private"
    };
}

/// <summary>단위 하나의 결과를 열쇠 번호로 모아 쓴다. 번호는 이 파일 안에서만 쓰고, 엔진이 열쇠로 다시 합친다.</summary>
sealed class Output
{
    readonly List<string> files = new List<string>();
    readonly Dictionary<string, int> fileIndex = new Dictionary<string, int>();
    readonly List<Decl> decls = new List<Decl>();
    readonly Dictionary<string, int> declIndex = new Dictionary<string, int>();
    readonly HashSet<(int, int, int, int, bool)> edges = new HashSet<(int, int, int, int, bool)>();
    readonly HashSet<(int, int, bool)> overrides = new HashSet<(int, int, bool)>();
    readonly HashSet<(int, int, int, string, string, int)> strings = new HashSet<(int, int, int, string, string, int)>();
    readonly HashSet<(int, int, int, string)> unresolved = new HashSet<(int, int, int, string)>();
    public readonly List<Dictionary<string, object>> Units = new List<Dictionary<string, object>>();
    /// <summary>각 소스 파일에서 수집한 의미 해석 오류다.</summary>
    public readonly List<Dictionary<string, object>> Diagnostics = new List<Dictionary<string, object>>();

    /// <summary>파일 번호.</summary>
    int File(string rel)
    {
        if (!fileIndex.TryGetValue(rel, out var i)) { i = files.Count; files.Add(rel); fileIndex[rel] = i; }
        return i;
    }

    /// <summary>선언 번호. 아직 걷지 않은 선언은 열쇠만 가진 자리로 먼저 만든다.</summary>
    int Index(string key)
    {
        if (!declIndex.TryGetValue(key, out var i)) { i = decls.Count; decls.Add(new Decl { Key = key }); declIndex[key] = i; }
        return i;
    }

    /// <summary>파일 하나의 결과를 합친다(같은 열쇠의 선언은 처음 것).</summary>
    public void Merge(FileResult r)
    {
        var f = File(r.File);
        Diagnostics.AddRange(r.Diagnostics);
        foreach (var d in r.Decls)
        {
            var i = Index(d.Key);
            if (decls[i].Kind == null) decls[i] = d;
            else decls[i].Occurrences.AddRange(d.Occurrences);
        }
        foreach (var e in r.Edges) edges.Add((Index(e.from), Index(e.to), f, e.line, e.write));
        foreach (var o in r.Overrides) overrides.Add((Index(o.member), o.target == null ? -1 : Index(o.target), o.external));
        foreach (var s in r.Strings) strings.Add((Index(s.from), f, s.line, s.api, s.name, s.type == null ? -1 : Index(s.type)));
        foreach (var u in r.Unresolved) unresolved.Add((Index(u.from), f, u.line, u.name));
    }

    /// <summary>바이너리로 쓴다.</summary>
    public void Write(string path)
    {
        using var stream = System.IO.File.Create(path);
        using var w = new BinaryValueWriter(stream);
        w.WriteStartObject();
        w.WriteNumber("version", 1);
        w.WriteStartArray("files");
        foreach (var f in files) w.WriteStringValue(f);
        w.WriteEndArray();
        w.WriteStartArray("decls");
        foreach (var d in decls)
        {
            w.WriteStartObject();
            w.WriteString("key", d.Key);
            if (d.Kind != null)
            {
                w.WriteString("name", d.Name);
                w.WriteString("source_name", d.SourceName ?? d.Name);
                w.WriteString("source_params", d.SourceParams ?? "");
                w.WriteString("kind", d.Kind);
                w.WriteNumber("file", File(d.File));
                w.WriteNumber("line", d.Line);
                w.WriteNumber("end", d.End);
                w.WriteNumber("container", d.Container == null ? -1 : Index(d.Container));
                w.WriteString("access", d.Access);
                w.WriteStartArray("occurrences");
                foreach (var part in d.Occurrences.Distinct().OrderBy(p => p.file).ThenBy(p => p.line))
                {
                    w.WriteStartObject();
                    w.WriteString("file", part.file); w.WriteNumber("line", part.line); w.WriteNumber("end", part.end);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                if (d.Type != null) w.WriteString("type", d.Type);
                if (d.Hash != null) { w.WriteString("hash", d.Hash); w.WriteNumber("stmts", d.Statements); }
                if (d.Locals >= 0) w.WriteNumber("locals", d.Locals);
                if (d.Variables.Count > 0)
                {
                    w.WriteStartArray("variables");
                    foreach (var variable in d.Variables)
                    {
                        w.WriteStartObject();
                        w.WriteString("name", variable.name);
                        w.WriteString("kind", variable.kind);
                        w.WriteNumber("line", variable.line);
                        w.WriteString("scope", variable.scope);
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                }
                Strings(w, "mods", d.Mods);
                Strings(w, "attrs", d.Attrs);
                Strings(w, "bases", d.Bases);
            }
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteStartArray("edges");
        foreach (var e in edges.OrderBy(x => x.Item1).ThenBy(x => x.Item2).ThenBy(x => x.Item3).ThenBy(x => x.Item4))
        {
            w.WriteStartArray();
            w.WriteNumberValue(e.Item1); w.WriteNumberValue(e.Item2); w.WriteNumberValue(e.Item3); w.WriteNumberValue(e.Item4);
            w.WriteNumberValue(e.Item5 ? 1 : 0);
            w.WriteEndArray();
        }
        w.WriteEndArray();
        w.WriteStartArray("overrides");
        foreach (var o in overrides.OrderBy(x => x.Item1).ThenBy(x => x.Item2))
        {
            w.WriteStartArray();
            w.WriteNumberValue(o.Item1); w.WriteNumberValue(o.Item2); w.WriteNumberValue(o.Item3 ? 1 : 0);
            w.WriteEndArray();
        }
        w.WriteEndArray();
        w.WriteStartArray("strings");
        foreach (var s in strings.OrderBy(x => x.Item1).ThenBy(x => x.Item3))
        {
            w.WriteStartArray();
            w.WriteNumberValue(s.Item1); w.WriteNumberValue(s.Item2); w.WriteNumberValue(s.Item3);
            w.WriteStringValue(s.Item4); w.WriteStringValue(s.Item5); w.WriteNumberValue(s.Item6);
            w.WriteEndArray();
        }
        w.WriteEndArray();
        w.WriteStartArray("unresolved");
        foreach (var u in unresolved.OrderBy(x => x.Item2).ThenBy(x => x.Item3))
        {
            w.WriteStartArray();
            w.WriteNumberValue(u.Item1); w.WriteNumberValue(u.Item2); w.WriteNumberValue(u.Item3); w.WriteStringValue(u.Item4);
            w.WriteEndArray();
        }
        w.WriteEndArray();
        w.WriteStartArray("diagnostics");
        foreach (var diagnostic in Diagnostics.OrderBy(x => (string)x["file"]).ThenBy(x => (int)x["line"]))
        {
            w.WriteStartObject();
            w.WriteString("file", (string)diagnostic["file"]);
            w.WriteNumber("line", (int)diagnostic["line"]);
            w.WriteString("code", (string)diagnostic["code"]);
            w.WriteString("message", (string)diagnostic["message"]);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteStartArray("units");
        foreach (var u in Units)
        {
            w.WriteStartObject();
            w.WriteString("name", (string)u["name"]);
            w.WriteNumber("errors", (int)u["errors"]);
            w.WriteNumber("walked", (int)u["walked"]);
            w.WriteNumber("ms", (int)u["ms"]);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteEndObject();
    }

    /// <summary>글자 배열 하나.</summary>
    static void Strings(BinaryValueWriter w, string name, List<string> values)
    {
        w.WriteStartArray(name);
        foreach (var v in values) w.WriteStringValue(v);
        w.WriteEndArray();
    }
}

/// <summary>추출기 작업 트리의 바이너리 입력.</summary>
sealed class BinaryValue
{
    readonly object Value;
    BinaryValue(object value) { Value = value; }
    public BinaryValue GetProperty(string name) => new BinaryValue(((Dictionary<string, object>)Value)[name]);
    public IEnumerable<BinaryValue> EnumerateArray() => ((List<object>)Value).Select(x => new BinaryValue(x));
    public string GetString() => (string)Value;
    public static BinaryValue Read(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream, new UTF8Encoding(false, true));
        if (Encoding.ASCII.GetString(reader.ReadBytes(4)) != "AIKR") throw new InvalidDataException("wire magic");
        var value = ReadValue(reader, reader.ReadByte(), 0);
        if (stream.Position != stream.Length) throw new InvalidDataException("wire trailing bytes");
        return new BinaryValue(value);
    }
    static object ReadValue(BinaryReader reader, byte tag, int depth)
    {
        if (depth > 256) throw new InvalidDataException("wire nesting limit");
        switch (tag)
        {
            case 0: return null;
            case 1: return false;
            case 2: return true;
            case 3: return reader.ReadInt64();
            case 4: return reader.ReadDouble();
            case 5:
                int size = checked((int)reader.ReadUInt32());
                if (size > 268435456) throw new InvalidDataException("wire string limit");
                var bytes = reader.ReadBytes(size);
                if (bytes.Length != size) throw new EndOfStreamException();
                return new UTF8Encoding(false, true).GetString(bytes);
            case 6:
                var list = new List<object>();
                byte item;
                while ((item = reader.ReadByte()) != 8) list.Add(ReadValue(reader, item, depth + 1));
                return list;
            case 7:
                var dict = new Dictionary<string, object>();
                byte key;
                while ((key = reader.ReadByte()) != 8)
                {
                    if (key != 5) throw new InvalidDataException("wire object key");
                    dict.Add((string)ReadValue(reader, key, depth + 1), ReadValue(reader, reader.ReadByte(), depth + 1));
                }
                return dict;
            default: throw new InvalidDataException("wire tag");
        }
    }
}

/// <summary>결과 객체·배열을 바이너리 스트림으로 직접 발행한다.</summary>
sealed class BinaryValueWriter : IDisposable
{
    readonly BinaryWriter Writer;
    public BinaryValueWriter(Stream stream)
    {
        Writer = new BinaryWriter(stream, new UTF8Encoding(false, true), true);
        Writer.Write(Encoding.ASCII.GetBytes("AIKR"));
    }
    public void WriteStartObject() => Writer.Write((byte)7);
    public void WriteEndObject() => Writer.Write((byte)8);
    public void WriteStartArray() => Writer.Write((byte)6);
    public void WriteStartArray(string name) { WriteStringValue(name); WriteStartArray(); }
    public void WriteEndArray() => Writer.Write((byte)8);
    public void WriteStringValue(string value)
    {
        if (value == null) { Writer.Write((byte)0); return; }
        var bytes = Encoding.UTF8.GetBytes(value);
        Writer.Write((byte)5); Writer.Write((uint)bytes.Length); Writer.Write(bytes);
    }
    public void WriteString(string name, string value) { WriteStringValue(name); WriteStringValue(value); }
    public void WriteNumberValue(int value) { Writer.Write((byte)3); Writer.Write((long)value); }
    public void WriteNumber(string name, int value) { WriteStringValue(name); WriteNumberValue(value); }
    public void Dispose() => Writer.Dispose();
}
