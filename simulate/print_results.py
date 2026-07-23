import csv

print('=' * 80)
print('PROTOTYPE D SIMULATION RESULTS: AES-GCM vs GMAC')
print('=' * 80)
print()

print('{:30} {:6} {:>14} {:>12} {:>8}'.format('Workload', 'Keymode', 'AES-GCM (us)', 'GMAC (us)', 'Speedup'))
print('-' * 80)
with open('results/speedup.csv') as f:
    for r in csv.DictReader(f):
        print('{:30} {:6} {:>14.1f} {:>12.1f} {:>7.3f}x'.format(
            r['workload'], r['keymode'],
            float(r['aes_gcm_us']), float(r['gmac_us']), float(r['speedup'])))
print()

print('Stage breakdown (GMAC cold-key):')
print('{:30} {:>10} {:>8} {:>8} {:>10} {:>10}'.format('Workload', 'CPU crypto', 'SWIOTLB', 'PCIe', 'GPU crypto', 'GPU kernel'))
print('-' * 80)
with open('results/summary.csv') as f:
    for r in csv.DictReader(f):
        if r['secmode'] == 'gmac' and r['keymode'] == 'cold':
            print('{:30} {:>10.1f} {:>8.1f} {:>8.1f} {:>10.1f} {:>10.1f}'.format(
                r['workload'],
                float(r['cpu_crypto_us']), float(r['swiotlb_us']),
                float(r['pcie_h2d_us']), float(r['gpu_crypto_us']),
                float(r['gpu_compute_us'])))
print()
print('Results saved to: simulate/results/')
print('Figures at:        simulate/results/figures/')
print('=' * 80)
