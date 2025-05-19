from pathlib import Path
import argparse
import csv
from collections import defaultdict

def scan_files(directory, extension):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    extension = extension.lstrip('.')
    pattern = f"*.{extension}"
    files = list(directory.rglob(pattern))

    output_csv = directory / "output.csv"
    summary = defaultdict(lambda: {'count': 0, 'size': 0.0})

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(files)} '.{extension}' files.\n")
    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    with output_csv.open(mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['file', 'size_kb'])

        total_size = 0
        for file in files:
            size_kb = file.stat().st_size / 1024
            total_size += size_kb

            relative_path = file.relative_to(directory)
            subfolder = relative_path.parent
            subfolder_key = subfolder.as_posix() + "/"

            # Update summary for each subfolder
            summary[subfolder_key]['count'] += 1
            summary[subfolder_key]['size'] += size_kb

            print(f"{str(relative_path):<40} {size_kb:>10.1f}")
            writer.writerow([str(relative_path), f"{size_kb:.1f}"])

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")
    print("Summary:")
    for subfolder, data in summary.items():
        print(f"  {subfolder:<15} —  {data['count']} files, {data['size']:.1f} KB")

    print(f"\nResults written to: {output_csv.resolve()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for files with a specific extension.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("-e", "--ext", default="txt", help="File extension to scan for (default: txt)")
    args = parser.parse_args()

    scan_files(args.path, args.ext)
