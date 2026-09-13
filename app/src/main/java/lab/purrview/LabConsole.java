package lab.purrview;

/** A fixed command interpreter. No OS process, filesystem or network access. */
public final class LabConsole {
    private boolean unlocked;
    public void unlock() { unlocked = true; }
    public void reset() { unlocked = false; }
    public String execute(String line) {
        if (!unlocked) return "Locked: reproduce the lab budget bypass first.";
        if (line == null || line.length() > 80) return "Rejected: command length limit is 80.";
        switch (line.trim()) {
            case "help": return "help | whoami | status | ls | cat note.txt | clear\nEducational and research purposes.";
            case "whoami": return "PurrView actor";
            case "status": return "Native size-policy bypass observed.\nConsole: simulated / app-local / no privileges gained.";
            case "ls": return "note.txt  [virtual fixture; no filesystem listing]";
            case "cat note.txt": return "Mochi: Bring treats at 18:00. [fictional record]";
            case "clear": return "";
            default: return "Unknown command. Type help. Commands are exact matches; shell syntax is not supported.";
        }
    }
}
