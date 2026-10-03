namespace ClauseTracker;

public record Step(string Dept, string Text, int Days);
public record ProcessDef(string Code, string Title, string Trigger, Step[] Steps)
{
    public int TotalDays => Steps.Sum(s => s.Days);
}

/// <summary>Static workflow configuration: departments, questions, processes C1–C5.</summary>
public static class Workflow
{
    public const string Exec = "التنفيذ";
    public const string Planning = "التخطيط";
    public const string Technical = "المراجعة الفنية";
    public const string Deputy = "مكتب النائب";
    public const string Stores = "المخازن";

    public static readonly string[] Departments = { Exec, Planning, Technical, Deputy, Stores };

    public static readonly Dictionary<string, string> QuestionText = new()
    {
        ["Q1"] = "هل يوجد تجاوز في البند؟",
        ["Q2"] = "هل للبند قيمة في العقد؟",
        ["Q3"] = "هل إجمالي قيمة التجاوزات يتجاوز إجمالي التكلفة؟",
    };

    public static readonly Dictionary<string, (string Value, string Label)[]> QuestionOptions = new()
    {
        ["Q1"] = new[] { ("yes", "نعم"), ("no", "لا") },
        ["Q2"] = new[] { ("yes", "نعم"), ("no", "لا") },
        ["Q3"] = new[]
        {
            ("above25", "زيادة أكثر من 25% عن إجمالي التكلفة"),
            ("upto25", "زيادة حتى 25% عن إجمالي التكلفة"),
            ("notexceed", "البند متجاوز لكن إجمالي القيمة لم يتجاوز"),
        },
    };

    public static string AnswerLabel(string q, string value) =>
        QuestionOptions[q].FirstOrDefault(o => o.Value == value).Label ?? value;

    const string ExecOver = "حصر كميات الأعمال المتجاوزة طبقًا للتنفيذ على الطبيعة وعمل مذكرة تجاوز بند وإرسالها إلى التخطيط مرفقًا بها أسباب التجاوز";

    public static readonly Dictionary<string, ProcessDef> Processes = new()
    {
        ["C1"] = new("C1", "لا يوجد تجاوز بنود ولا إجمالي تجاوز", "لا يوجد تجاوز في البند", new[]
        {
            new Step(Exec, "مراجعة كافة الملفات والرسومات والتوقيع", 3),
            new Step(Technical, "مراجعة المستخلص وتوقيع رئيس القطاع", 4),
            new Step(Stores, "مراجعة المخازن ثم الإرسال إلى الصرف", 2),
        }),
        ["C2"] = new("C2", "بند متجاوز وإجمالي القيمة لم يتجاوز", "بند متجاوز وإجمالي القيمة لم يتجاوز", new[]
        {
            new Step(Exec, ExecOver, 4),
            new Step(Planning, "مراجعة مذكرة التجاوز وإرسال الموافقة على تعديل الكميات في أمر التكليف من قبول العمل", 2),
            new Step(Technical, "مراجعة المستخلص مع موافقة التخطيط ثم إرساله إلى المخازن ولا يستلزم موافقة رئيس القطاعات", 4),
            new Step(Stores, "مراجعة المخازن وإرساله إلى الصرف", 2),
        }),
        ["C3"] = new("C3", "تجاوز داخل 25% من قيمة أمر التكليف", "تجاوز حتى 25% من قيمة أمر التكليف", new[]
        {
            new Step(Exec, ExecOver, 4),
            new Step(Planning, "يتم الحصول على موافقة التخطيط على التجاوز طبقًا للأسباب الواردة من التنفيذ", 3),
            new Step(Technical, "يتم الحصول على موافقة رئيس القطاعات من خلال المراجعة الفنية للتنفيذ طبقًا لما يتم حاليًا", 5),
            new Step(Stores, "مراجعة المخازن وإرساله إلى الصرف", 2),
        }),
        ["C4"] = new("C4", "تجاوز أكثر من 25% من قيمة أمر التكليف", "تجاوز أكثر من 25% من قيمة أمر التكليف", new[]
        {
            new Step(Exec, ExecOver, 4),
            new Step(Planning, "مراجعة مذكرة التجاوز وعمل مذكرة لرفعها للموافقة ورئيس القطاعات والنائب", 3),
            new Step(Technical, "مراجعة إجمالي قيمة التجاوزات", 5),
            new Step(Deputy, "اعتماد تعديل/زيادة قيمة أمر التكليف طبقًا للإجراءات المعتمدة", 5),
            new Step(Stores, "لا يتم العرض على اللجنة العليا إلا في حالة زيادة الاتفاقية الإطارية أو إضافة بنود ليس لها سعر، وفي غير ذلك يتم تعديل قيمة أمر التكليف وعمل أمر تكليف جديد وإرساله إلى الصرف", 10),
        }),
        ["C5"] = new("C5", "البند ليس له قيمة في العقد", "البند ليس له قيمة في العقد", new[]
        {
            new Step(Exec, "يتم اتخاذ الإجراءات طبقًا لما تم الإشارة إليه في البنود السابقة، بحسب حالة التجاوز والقيمة الإجمالية", 39),
        }),
    };
}
