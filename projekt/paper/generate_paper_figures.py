import os
import sys
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import SessionLocal
from database.tables import Anomaly, ModelInfo, NetworkMetric

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

#pobieranie danych z bazy

def get_data_from_db():
    with SessionLocal() as session:
        anomalies = session.query(
            Anomaly.timestamp,
            ModelInfo.algorithm_type,
            Anomaly.anomaly_score,
            Anomaly.severity_level
        ).join(ModelInfo, Anomaly.model_id == ModelInfo.id).order_by(Anomaly.timestamp).all()

        df_anomalies = pd.DataFrame(anomalies, columns=[
            'timestamp', 'algorithm_type', 'anomaly_score', 'severity_level'
        ])

        metrics = session.query(
            NetworkMetric.timestamp,
            NetworkMetric.syn_to_ack_ratio
        ).order_by(NetworkMetric.timestamp).all()

        df_metrics = pd.DataFrame(metrics, columns=[
            'timestamp', 'syn_to_ack_ratio'
        ])

    logger.info(f"Retrieved {len(df_anomalies)} anomalies and {len(df_metrics)} metrics")
    return df_anomalies, df_metrics

#normalizacja czasu

def normalize_time(df_anomalies):
    df_anomalies['minutes_elapsed'] = df_anomalies.groupby('algorithm_type')['timestamp'].transform(
        lambda x: (x - x.min()).dt.total_seconds() / 60
    )
    return df_anomalies

#wykres 1 - subplots z oznaczeniem ataku

def plot_subplots_with_attack(df_anomalies):
    fig, axes = plt.subplots(3, 1, figsize=(14, 12), sharex=True)
    fig.suptitle('Anomaly Scores Over Time: Model Comparison (Normalized Time)', fontsize=16, fontweight='bold', y=0.98)
    
    models = ['IsolationForest', 'OneClassSVM', 'Threshold']
    colors = ['#1f77b4', '#ff7f0e', '#d62728']
    
    for i, model in enumerate(models):
        ax = axes[i]
        model_data = df_anomalies[df_anomalies['algorithm_type'] == model]
        
        if len(model_data) > 0:

            #obliczanie statystyk

            mean_score = model_data['anomaly_score'].mean()
            std_score = model_data['anomaly_score'].std()
            count = len(model_data)
            
            #rysowanie linii

            ax.plot(model_data['minutes_elapsed'], model_data['anomaly_score'], 
                    marker='.', linestyle='-', color=colors[i], markersize=6, linewidth=1.5,
                    label=f'n={count}, mean={mean_score:.3f}, std={std_score:.3f}')
            
            #oznaczenie momentu ataku (przy założeniu, że atak zaczyna się po 2 minutach dla IF, 1 min dla OC-SVM, 0 min dla Threshold)
            
            if model == 'IsolationForest':
                attack_time = 4.0  #szacunkowo na podstawie danych
            elif model == 'OneClassSVM':
                attack_time = 2.5
            else:
                attack_time = 0.5
            
            ax.axvline(x=attack_time, color='red', linestyle='--', linewidth=2, alpha=0.7, label='Attack Start')
            
            ax.set_ylabel('Anomaly Score', fontsize=12, fontweight='bold')
            ax.set_title(f'{model} (mean={mean_score:.3f}, std={std_score:.3f})', 
                        fontsize=13, fontweight='bold', loc='left', pad=10)
            ax.legend(loc='best', fontsize=9)
            ax.grid(True, alpha=0.3, linestyle=':')
            ax.set_xlim(left=0)
    
    axes[2].set_xlabel('Time elapsed from test start (minutes)', fontsize=12, fontweight='bold')
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig('paper/figures/fig1_subplots_comparison.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 1 (subplots): paper/figures/fig1_subplots_comparison.png")
    plt.close()

#wykres 2 - boxplot IF vs OC-SVM

def plot_boxplot_if_svm(df_anomalies):
    plt.figure(figsize=(10, 6))
    
    df_filtered = df_anomalies[df_anomalies['algorithm_type'].isin(['IsolationForest', 'OneClassSVM'])]
    
    sns.boxplot(
        data=df_filtered,
        x='algorithm_type',
        y='anomaly_score',
        palette="Set2",
        showfliers=True,
        width=0.6
    )
    
    plt.title('Distribution of Anomaly Scores: Isolation Forest vs. One-Class SVM', fontsize=14, fontweight='bold')
    plt.xlabel('Detection Model', fontsize=12, fontweight='bold')
    plt.ylabel('Anomaly Score', fontsize=12, fontweight='bold')
    plt.grid(True, axis='y', alpha=0.3, linestyle=':')
    plt.ylim(-1.0, 0.1)
    plt.tight_layout()
    plt.savefig('paper/figures/fig2_boxplot_if_svm.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 2 (boxplot IF vs SVM): paper/figures/fig2_boxplot_if_svm.png")
    plt.close()

#wykres 3 - boxplot Threshold

def plot_boxplot_threshold(df_anomalies):
    plt.figure(figsize=(10, 6))
    
    df_threshold = df_anomalies[df_anomalies['algorithm_type'] == 'Threshold']
    
    sns.boxplot(
        data=df_threshold,
        x='algorithm_type',
        y='anomaly_score',
        palette="Set2",
        showfliers=True,
        width=0.6
    )
    
    plt.title('Distribution of Anomaly Scores: Threshold Method', fontsize=14, fontweight='bold')
    plt.xlabel('Detection Model', fontsize=12, fontweight='bold')
    plt.ylabel('Anomaly Score', fontsize=12, fontweight='bold')
    plt.grid(True, axis='y', alpha=0.3, linestyle=':')
    plt.tight_layout()
    plt.savefig('paper/figures/fig3_boxplot_threshold.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 3 (boxplot Threshold): paper/figures/fig3_boxplot_threshold.png")
    plt.close()

#tabela statystyk

def generate_statistics_table(df_anomalies):
    stats = df_anomalies.groupby(['algorithm_type'])['anomaly_score'].agg([
        'count', 'mean', 'std', 'min', 'max'
    ]).round(4)

    stats.to_csv('paper/data/table1_statistics.csv')
    logger.info("Saved statistics table: paper/data/table1_statistics.csv")
    print("\nStatystyki:")
    print(stats)
    return stats

def generate_all():
    logger.info("Starting generation of plots for the paper...")

    os.makedirs('paper/figures', exist_ok=True)
    os.makedirs('paper/data', exist_ok=True)

    df_anomalies, df_metrics = get_data_from_db()

    if len(df_anomalies) == 0:
        logger.error("No data available in the database.")
        return

    #normalizacja czasu

    df_anomalies = normalize_time(df_anomalies)

    df_anomalies.to_csv('paper/data/anomalies_export.csv', index=False)
    logger.info("Saved data: paper/data/anomalies_export.csv")

    sns.set_theme(style="whitegrid", font="DejaVu Sans", rc={"axes.grid": True})
    plt.rcParams['figure.dpi'] = 300
    plt.rcParams['font.size'] = 11

    plot_subplots_with_attack(df_anomalies)
    plot_boxplot_if_svm(df_anomalies)
    plot_boxplot_threshold(df_anomalies)
    generate_statistics_table(df_anomalies)

    logger.info("Done! Check the paper/figures/ and paper/data/ folders")

if __name__ == "__main__":
    generate_all()