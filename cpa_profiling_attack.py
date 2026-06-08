# %% [markdown]
# # CPA + Profiling DL SCA

# %% [markdown]
# Profiling Side-channell attack in a single trace scenario, using keccak.vhd implementation.
# 
# The internal non-linear states (recovery bits) are extracted directly from the physical measurements (traces). These extracted continuous marginal probabilities are formatted into an exported payload tailored to instantiate a Soft Analytical Side-Channel Attack (SASCA) framework driven by a Factor Graph and solved via the Belief Propagation algorithm.

# %% [markdown]
# ### Imports

# %%
import h5py
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

# %% [markdown]
# ### Keccak implementation simulation
# 
# Emulation of the round 1 sequence from keccak.vhd (Keccak-f 1600) implementation. 

# %% [markdown]
# Rotation function -> 64-bits left rotation that emulate the rol rotation in the keccak implementation

# %%
def bit_rotate_left(val, shift):
    # 64-bits left rotation (rol in keccak.vhd)
    return ((val << shift) & 0xFFFFFFFFFFFFFFFF) | (val >> (64 - shift))

# %% [markdown]
# Round1 Chi Computation -> it emulates the whole 1600-bit state (theta -> rho -> pi -> chi) and returns the output of the chi-function (S-box)
# 
# - State Initialization: S is initialized, the 64-bit message block msg is mapped into S[0, 0] and the remaining 24 lanes are initialized to zero.
# 
# - Theta Step: computes the parity of each column C[x] and diffuses it to near columns via bitwise XOR and rotation (bit_rotate_left).
# 
# - Rho and Pi Steps: bit-level dispersion applying fixed asymmetric coordinate mapping and cyclical bit shifting across the 25 lanes using exact offsets (taken from implementation)
# 
# - Chi Step: non-linear layer of Keccak
# 
# $$\chi_{\text{out}}(x,y) = \rho\pi(x,y) \oplus (\neg\rho\pi(x+1,y) \land \rho\pi(x+2,y))$$
# 

# %%
def compute_round1_chi_full(msg_array):
    # It emulate the whole 1600-bit state (theta -> rho -> pi -> chi)
    # It returns the output of the chi-function
    N = len(msg_array)
    
    # State initialization (5x5)
    S = np.zeros((5, 5, N), dtype=np.uint64)
    S[0, 0] = msg_array.astype(np.uint64) # reg_s(0,0) <= msg
    
    # THETA 
    C = np.zeros((5, N), dtype=np.uint64)
    for x in range(5):
        C[x] = S[x,0] ^ S[x,1] ^ S[x,2] ^ S[x,3] ^ S[x,4]
        
    D = np.zeros((5, N), dtype=np.uint64)
    for x in range(5):
        D[x] = C[(x-1)%5] ^ bit_rotate_left(C[(x+1)%5], 1)
        
    theta_out = np.zeros((5, 5, N), dtype=np.uint64)
    for x in range(5):
        for y in range(5):
            theta_out[x, y] = S[x, y] ^ D[x]
            
    # RHO and PI
    rho_pi = np.zeros((5, 5, N), dtype=np.uint64)
    offsets = {
        (0,0): (0,0,0),  (0,2): (1,0,1),  (0,4): (2,0,62), (0,1): (3,0,28), (0,3): (4,0,27),
        (1,3): (0,1,36), (1,0): (1,1,44), (1,2): (2,1,6),  (1,4): (3,1,55), (1,1): (4,1,20),
        (2,1): (0,2,3),  (2,3): (1,2,10), (2,0): (2,2,43), (2,2): (3,2,25), (2,4): (4,2,39),
        (3,4): (0,3,41), (3,1): (1,3,45), (3,3): (2,3,15), (3,0): (3,3,21), (3,2): (4,3,8),
        (4,2): (0,4,18), (4,4): (1,4,2),  (4,1): (2,4,61), (4,3): (3,4,56), (4,0): (4,4,14)
    }
    for (x_out, y_out), (x_in, y_in, shift) in offsets.items():
        rho_pi[x_out, y_out] = bit_rotate_left(theta_out[x_in, y_in], shift)
        
    # CHI (S-box output)
    chi_out = np.zeros((5, 5, N), dtype=np.uint64)
    for x in range(5):
        for y in range(5):
            chi_out[x, y] = rho_pi[x, y] ^ ((~rho_pi[(x+1)%5, y]) & rho_pi[(x+2)%5, y])
            
    return chi_out, S

# %% [markdown]
# ### Load Dataset
# 
# From the random dataset, 9900 of the 10000 traces and inputs are used to train the model, the reamining 100 are used to perform the final profiling attack.

# %%
with h5py.File("../keccak_unprotected.h5", "r") as f:
    traces = np.array(f["random/traces"], dtype=np.float32)
    inputs = np.array(f["random/inputs"], dtype=np.uint8)

attack_traces = traces[9900:]
attack_inputs = inputs[9900:]

traces = traces[:9900]
inputs = inputs[:9900]


print("Traces:", traces.shape)
print("Inputs:", inputs.shape)


print("Attack Traces:", attack_traces.shape)
print("Attack Inputs:", attack_inputs.shape)

# %% [markdown]
# Calculate Round 1 from dataset inputs

# %%
msg = np.zeros(len(inputs), dtype=np.uint64)
for i in range(8):
    msg |= inputs[:, i].astype(np.uint64) << (i * 8)

# State before and after chi function
chi_state_target, state_initial = compute_round1_chi_full(msg)

# %% [markdown]
# Hamming Distance of all 25 lanes

# %%
hd_leakage = np.zeros(len(msg), dtype=np.float32)
for x in range(5):
    for y in range(5):
        diff = state_initial[x, y] ^ chi_state_target[x, y]
        lane_hd = np.array([bin(int(v)).count("1") for v in diff], dtype=np.float32)
        hd_leakage += lane_hd

# select the recovery_bits from the lane (3,0)
recovery_lane = chi_state_target[3, 0]  
labels = np.zeros((len(msg), 64), dtype=np.float32)
for i in range(64):
    labels[:, i] = (recovery_lane >> i) & 1

# %%
attack_msg = np.zeros(len(attack_inputs), dtype=np.uint64)

for i in range(8):
    attack_msg |= attack_inputs[:, i].astype(np.uint64) << (i * 8)

# %%
attack_labels = np.zeros((len(attack_msg), 64), dtype=np.float32)

for i in range(64):
    attack_labels[:, i] = (attack_msg >> i) & 1

# %% [markdown]
# ### CPA
# 
# Correlation and POI selection

# %%
corrs = []
stds = np.std(traces, axis=0)
for t in range(traces.shape[1]):
    if stds[t] < 1e-6:
        corrs.append(0.0)
    else:
        corr = np.corrcoef(traces[:, t], hd_leakage)[0, 1]
        corrs.append(0.0 if np.isnan(corr) else corr)
corrs = np.array(corrs)

top_k_POI = np.argsort(np.abs(corrs))[-50:]
print("Best 50 POIs:", top_k_POI)
print("Max correlation found:", np.max(np.abs(corrs)))

# %% [markdown]
# ### DL Profiling using CNN

# %%
X_poi = traces[:, top_k_POI]
X_train, X_test, y_train, y_test = train_test_split(X_poi, labels, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

X_train_cnn = X_train_scaled.reshape((X_train_scaled.shape[0], X_train_scaled.shape[1], 1))
X_test_cnn = X_test_scaled.reshape((X_test_scaled.shape[0], X_test_scaled.shape[1], 1))

X_tr, X_val, y_tr, y_val = train_test_split(X_train_cnn, y_train, test_size=0.2, random_state=42)


# %% [markdown]
# #### Hyperparameter Tuning

# %%
def tune_hyperparameters(X_tr, y_tr, X_val, y_val):
    best_acc = 0
    best_config = {}
    
    param_grid = {'filters': [16, 32], 'lr': [1e-3, 5e-4], 'dropout': [0.3, 0.5]}
    
    for filters in param_grid['filters']:
        for lr in param_grid['lr']:
            for d_rate in param_grid['dropout']:
                model = tf.keras.Sequential([
                    tf.keras.layers.Input(shape=(X_tr.shape[1], 1)),
                    tf.keras.layers.Conv1D(filters=filters, kernel_size=3, activation='relu', padding='same'),
                    tf.keras.layers.BatchNormalization(),
                    tf.keras.layers.Flatten(),
                    tf.keras.layers.Dense(64, activation='relu'),
                    tf.keras.layers.Dropout(d_rate),
                    tf.keras.layers.Dense(64, activation='sigmoid')
                ])
                model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=lr),
                              loss='binary_crossentropy', metrics=['binary_accuracy'])
                
                history = model.fit(X_tr, y_tr, validation_data=(X_val, y_val), epochs=5, batch_size=64, verbose=0)
                val_acc = max(history.history['val_binary_accuracy'])
                print(f"Config -> Filters: {filters}, LR: {lr}, Dropout: {d_rate} | Val Accuracy: {val_acc:.4f}")
                
                if val_acc > best_acc:
                    best_acc = val_acc
                    best_config = {'filters': filters, 'lr': lr, 'dropout': d_rate}
                    
    print("Best configuration:", best_config)
    return best_config

best_hparams = tune_hyperparameters(X_tr, y_tr, X_val, y_val)


# %% [markdown]
# #### Best Model Training

# %%
final_model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(X_train_cnn.shape[1], 1)),
    tf.keras.layers.Conv1D(filters=best_hparams['filters'], kernel_size=3, activation='relu', padding='same'),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.AveragePooling1D(pool_size=2),
    
    tf.keras.layers.Conv1D(filters=best_hparams['filters'] * 2, kernel_size=3, activation='relu', padding='same'),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.AveragePooling1D(pool_size=2),
    
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),
    tf.keras.layers.Dropout(best_hparams['dropout']),
    tf.keras.layers.Dense(64, activation='sigmoid') 
])

final_model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=best_hparams['lr']),
    loss='binary_crossentropy',
    metrics=['binary_accuracy']
)

early_stopping = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=6, restore_best_weights=True)

final_model.fit(
    X_train_cnn, y_train,
    validation_split=0.2,
    epochs=40,
    batch_size=64,
    callbacks=[early_stopping],
    verbose=1
)

# %% [markdown]
# ### Profiling attack
# 
# Profiling attack on the 100 traces of the attack dataset, using cnn.

# %%
attack_poi = attack_traces[:, top_k_POI]
attack_poi = scaler.transform(attack_poi)
attack_poi = attack_poi.reshape((attack_poi.shape[0], attack_poi.shape[1], 1))

attack_probs = final_model.predict(attack_poi)
attack_preds = (attack_probs > 0.5).astype(int)

# print(attack_preds.shape, attack_labels.shape)

print("Final report on cnn metrics on attact datas:")
print(classification_report(attack_labels.flatten(), attack_preds.flatten()))

# %%
bit_accuracy = np.mean(attack_preds == attack_labels)
print("Bit accuracy:", bit_accuracy * 100, "%")

# %% [markdown]
# Bit accuracy trace by trace (for attack data)

# %%
for trace_id in range(len(attack_labels)):

    correct = np.sum(attack_preds[trace_id] == attack_labels[trace_id])

    print(
        f"Trace {trace_id:4d} -> "
        f"{correct:2d}/64 bits correct "
        f"({100*correct/64:.2f}%)"
    )


